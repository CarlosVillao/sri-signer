import express from 'express';
import cors from 'cors';
import axios from 'axios';
import nodemailer from 'nodemailer';
import forge from 'node-forge';
import { XMLValidator } from 'fast-xml-parser';
import { createHash } from 'crypto';
import { DOMParser } from '@xmldom/xmldom';
import * as xadesjs from 'xadesjs';
import { Crypto } from '@peculiar/webcrypto';

const app = express();

app.use(cors());
app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 3000;
const SERVICE_VERSION = '1.0.6-p12-selected-cert';

xadesjs.Application.setEngine(
  'NodeJS',
  new Crypto()
);

// URLs SRI Ecuador
const SRI_URLS = {
  '1': {
    recepcion:
      'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl',
    autorizacion:
      'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl',
  },
  '2': {
    recepcion:
      'https://cel.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl',
    autorizacion:
      'https://cel.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl',
  },
};

// ======================================================
// PKCS12 HELPERS
// ======================================================

function getPkcs12(p12Buffer, password) {
  try {
    const p12Asn1 = forge.asn1.fromDer(
      p12Buffer.toString('binary')
    );

    return forge.pkcs12.pkcs12FromAsn1(
      p12Asn1,
      false,
      password
    );
  } catch (error) {
    if (
      String(error?.message ?? '').includes(
        'Invalid password'
      )
    ) {
      throw new Error(
        'No se pudo abrir el archivo .p12. Verifica que la contraseña sea correcta.'
      );
    }

    throw new Error(
      `No se pudo leer el archivo .p12: ${error.message}`
    );
  }
}

function isCertificateAuthority(cert) {
  const basicConstraints =
    cert.getExtension &&
    cert.getExtension('basicConstraints');

  return Boolean(
    basicConstraints &&
      basicConstraints.cA
  );
}

function rsaPrivateKeyMatchesCertificate(
  privateKey,
  cert
) {
  return Boolean(
    privateKey?.n &&
      privateKey?.e &&
      cert?.publicKey?.n &&
      cert?.publicKey?.e &&
      privateKey.n.compareTo(
        cert.publicKey.n
      ) === 0 &&
      privateKey.e.compareTo(
        cert.publicKey.e
      ) === 0
  );
}

function certToBase64Der(cert) {
  return Buffer.from(
    forge.asn1
      .toDer(
        forge.pki.certificateToAsn1(cert)
      )
      .getBytes(),
    'binary'
  ).toString('base64');
}

function privateKeyToPkcs8Der(privateKey) {
  const privateKeyAsn1 =
    forge.pki.privateKeyToAsn1(
      privateKey
    );

  const privateKeyInfo =
    forge.pki.wrapRsaPrivateKey(
      privateKeyAsn1
    );

  return Buffer.from(
    forge.asn1
      .toDer(privateKeyInfo)
      .getBytes(),
    'binary'
  );
}

function getCertificateDescription(cert) {
  return cert.subject.attributes
    .map(
      (a) =>
        `${a.shortName || a.name}=${a.value}`
    )
    .join(' | ');
}

function getCertificateValues(cert) {
  const subjectValues =
    cert.subject.attributes.map((a) =>
      String(a.value ?? '')
    );

  const extensionValues = (
    cert.extensions || []
  ).flatMap((ext) => [
    String(ext.value ?? ''),
    ...(
      ext.altNames || []
    ).map((alt) =>
      String(alt.value ?? '')
    ),
  ]);

  return [
    ...subjectValues,
    ...extensionValues,
  ];
}

function extraerMaterialFirma(
  p12Buffer,
  password
) {
  const p12 = getPkcs12(
    p12Buffer,
    password
  );

  const certBags =
    p12.getBags({
      bagType:
        forge.pki.oids.certBag,
    })[
      forge.pki.oids.certBag
    ] || [];

  const shroudedKeyBags =
    p12.getBags({
      bagType:
        forge.pki.oids
          .pkcs8ShroudedKeyBag,
    })[
      forge.pki.oids
        .pkcs8ShroudedKeyBag
    ] || [];

  const keyBags =
    p12.getBags({
      bagType:
        forge.pki.oids.keyBag,
    })[
      forge.pki.oids.keyBag
    ] || [];

  const privateKeys = [
    ...shroudedKeyBags,
    ...keyBags,
  ]
    .map((bag) => bag.key)
    .filter(Boolean);

  const now = new Date();

  const candidates = certBags
    .map((bag, index) => ({
      cert: bag.cert,
      index,
    }))
    .filter(({ cert }) => cert)
    .filter(
      ({ cert }) =>
        !isCertificateAuthority(cert)
    )
    .map(({ cert, index }) => ({
      cert,
      certIndex: index,
      privateKey: privateKeys.find(
        (key) =>
          rsaPrivateKeyMatchesCertificate(
            key,
            cert
          )
      ),
      isCurrentlyValid:
        cert.validity.notBefore <= now &&
        cert.validity.notAfter > now,
    }))
    .filter(
      ({ privateKey }) => privateKey
    )
    .sort((a, b) => {
      if (
        a.isCurrentlyValid !==
        b.isCurrentlyValid
      ) {
        return a.isCurrentlyValid
          ? -1
          : 1;
      }

      return (
        b.cert.validity.notAfter -
        a.cert.validity.notAfter
      );
    });

  const selected = candidates[0];

  if (!selected) {
    throw new Error(
      'El archivo .p12 no contiene un certificado válido con llave privada compatible.'
    );
  }

  const {
    cert,
    privateKey,
    certIndex,
    isCurrentlyValid,
  } = selected;

  const subject =
    getCertificateDescription(cert);

  const issuer =
    cert.issuer.attributes
      .map(
        (a) =>
          `${a.shortName || a.name}=${a.value}`
      )
      .join(' | ');

  return {
    cert,
    privateKey,
    certDerBase64:
      certToBase64Der(cert),
    certIndex,
    subject,
    issuer,
    values:
      getCertificateValues(cert),
    validFrom:
      cert.validity.notBefore,
    validTo:
      cert.validity.notAfter,
    isCurrentlyValid,
    totalCertsEnP12:
      certBags.length,
    totalLlavesEnP12:
      privateKeys.length,
    nowUtc: now.toISOString(),
  };
}

// ======================================================
// FIRMA XAdES-BES
// ======================================================

async function firmarXML(
  xmlString,
  materialFirma
) {
  const crypto = new Crypto();

  const key =
    await crypto.subtle.importKey(
      'pkcs8',
      privateKeyToPkcs8Der(
        materialFirma.privateKey
      ),
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
      },
      false,
      ['sign']
    );

  const xmlDoc =
    new DOMParser().parseFromString(
      xmlString,
      'text/xml'
    );

  const signedXml =
    new xadesjs.SignedXml(xmlDoc);

  await signedXml.Sign(
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: {
        name: 'SHA-256',
      },
    },
    key,
    xmlDoc,
    {
      references: [
        {
          hash: 'SHA-256',
          transforms: [
            'enveloped',
          ],
        },
      ],
      signingCertificate:
        materialFirma.certDerBase64,
    }
  );

  return signedXml.toString();
}

// ======================================================
// XML HELPERS
// ======================================================

function getTag(xml, tagName) {
  return (
    xml.match(
      new RegExp(
        `<${tagName}>(.*?)</${tagName}>`
      )
    )?.[1]?.trim() ?? null
  );
}

function hashXml(xml) {
  return createHash('sha256')
    .update(xml, 'utf8')
    .digest('hex');
}

function limpiarXml(xml) {
  return String(xml ?? '')
    .replace(/^\uFEFF/, '')
    .trim();
}

function diagnosticarXml(xml) {
  const limpio = limpiarXml(xml);

  const validation =
    XMLValidator.validate(limpio);

  const namespaces =
    limpio.match(
      /\sxmlns(?::\w+)?=/g
    ) ?? [];

  const ambiente =
    getTag(limpio, 'ambiente');

  const clave =
    getTag(
      limpio,
      'claveAcceso'
    );

  const ruc =
    getTag(limpio, 'ruc');

  const errores = [];

  if (validation !== true) {
    errores.push(
      `XML mal formado: ${
        validation.err?.msg ??
        'error no especificado'
      }`
    );
  }

  if (namespaces.length > 0) {
    errores.push(
      `El XML sin firmar no debe traer namespaces (${namespaces.join(
        ', '
      )}).`
    );
  }

  if (
    clave &&
    clave.length !== 49
  ) {
    errores.push(
      'La clave de acceso debe tener 49 dígitos.'
    );
  }

  if (
    clave &&
    ambiente &&
    clave.slice(23, 24) !== ambiente
  ) {
    errores.push(
      `La clave tiene ambiente ${clave.slice(
        23,
        24
      )} pero el XML ambiente ${ambiente}.`
    );
  }

  return {
    ok: errores.length === 0,
    errores,
    resumen: {
      sha256: hashXml(limpio),
      longitud:
        Buffer.byteLength(
          limpio,
          'utf8'
        ),
      ruc,
      ambiente,
      claveAcceso: clave
        ? `${clave.slice(
            0,
            10
          )}...${clave.slice(-6)}`
        : null,
      secuencial: getTag(
        limpio,
        'secuencial'
      ),
      total: getTag(
        limpio,
        'importeTotal'
      ),
      namespacesDetectados:
        namespaces.length,
    },
  };
}

function extraerCertificado(
  p12Buffer,
  password
) {
  return extraerMaterialFirma(
    p12Buffer,
    password
  );
}

function validarCertificadoContraXml({
  xml,
  certInfo,
}) {
  const rucXml =
    getTag(xml, 'ruc');

  const ambienteXml =
    getTag(xml, 'ambiente');

  const claveXml =
    getTag(
      xml,
      'claveAcceso'
    );

  const now = new Date();

  if (certInfo.validTo < now) {
    return `El certificado .p12 está vencido desde ${certInfo.validTo
      .toISOString()
      .slice(0, 10)}.`;
  }

  if (certInfo.validFrom > now) {
    return `El certificado .p12 todavía no está vigente.`;
  }

  if (rucXml) {
    const cedulaDelRuc =
      rucXml.slice(0, 10);

    const perteneceAlRuc =
      certInfo.values.some(
        (value) =>
          value.includes(rucXml) ||
          value.includes(
            cedulaDelRuc
          )
      );

    if (!perteneceAlRuc) {
      return `El certificado .p12 no corresponde al RUC ${rucXml}.`;
    }
  }

  if (
    claveXml?.length === 49 &&
    ambienteXml &&
    claveXml.slice(23, 24) !==
      ambienteXml
  ) {
    return `La clave de acceso tiene ambiente ${claveXml.slice(
      23,
      24
    )}, pero el XML tiene ambiente ${ambienteXml}.`;
  }

  return null;
}

// ======================================================
// ENVÍO SOAP AL SRI
// ======================================================

async function enviarRecepcion(
  xmlFirmado,
  ambiente
) {
  const xmlSinDeclaracion =
    xmlFirmado
      .replace(
        /<\?xml.*?\?>/,
        ''
      )
      .trim();

  const soap = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ec="http://ec.gob.sri.ws.recepcion">
  <soapenv:Header/>
  <soapenv:Body>
    <ec:validarComprobante>
      <xml><![CDATA[${xmlSinDeclaracion}]]></xml>
    </ec:validarComprobante>
  </soapenv:Body>
</soapenv:Envelope>`;

  const url =
    SRI_URLS[
      ambiente
    ].recepcion.replace(
      '?wsdl',
      ''
    );

  try {
    const res = await axios.post(
      url,
      soap,
      {
        headers: {
          'Content-Type':
            'text/xml; charset=utf-8',
          SOAPAction: '',
        },
        timeout: 60000,
      }
    );

    const estadoMatch =
      res.data.match(
        /<estado>(.*?)<\/estado>/
      );

    return {
      estado:
        estadoMatch?.[1] ??
        'DESCONOCIDO',
      raw: res.data,
      mensajes:
        extraerMensajesSri(
          res.data
        ),
    };
  } catch (error) {
    return {
      estado: 'ERROR_RED',
      raw: error.message,
      mensajes: [
        {
          identificador:
            error.code ||
            'NETWORK',
          mensaje:
            error.message,
          tipo: 'ERROR',
        },
      ],
    };
  }
}

function extraerMensajesSri(
  rawXml
) {
  const doc =
    new DOMParser().parseFromString(
      rawXml,
      'text/xml'
    );

  const nodes = Array.from(
    doc.getElementsByTagName(
      'mensaje'
    )
  );

  return nodes
    .map((node) => ({
      identificador:
        node.getElementsByTagName(
          'identificador'
        )[0]?.textContent ??
        null,
      mensaje:
        node.getElementsByTagName(
          'mensaje'
        )[0]?.textContent ??
        null,
      informacionAdicional:
        node.getElementsByTagName(
          'informacionAdicional'
        )[0]?.textContent ??
        null,
      tipo:
        node.getElementsByTagName(
          'tipo'
        )[0]?.textContent ??
        null,
    }))
    .filter(
      (m) =>
        m.identificador ||
        m.mensaje ||
        m.informacionAdicional ||
        m.tipo
    );
}

async function consultarAutorizacion(
  claveAcceso,
  ambiente
) {
  const soap = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ec="http://ec.gob.sri.ws.autorizacion">
  <soapenv:Body>
    <ec:autorizacionComprobante>
      <claveAccesoComprobante>${claveAcceso}</claveAccesoComprobante>
    </ec:autorizacionComprobante>
  </soapenv:Body>
</soapenv:Envelope>`;

  const url =
    SRI_URLS[
      ambiente
    ].autorizacion.replace(
      '?wsdl',
      ''
    );

  const res = await axios.post(
    url,
    soap,
    {
      headers: {
        'Content-Type':
          'text/xml; charset=utf-8',
        SOAPAction: '',
      },
      timeout: 30000,
    }
  );

  const doc =
    new DOMParser().parseFromString(
      res.data,
      'text/xml'
    );

  return {
    estado:
      doc.getElementsByTagName(
        'estado'
      )[0]?.textContent ??
      'NO_AUTORIZADO',

    numeroAutorizacion:
      doc.getElementsByTagName(
        'numeroAutorizacion'
      )[0]?.textContent ??
      null,

    fechaAutorizacion:
      doc.getElementsByTagName(
        'fechaAutorizacion'
      )[0]?.textContent ??
      null,

    mensajes:
      extraerMensajesSri(
        res.data
      ),

    raw: res.data,
  };
}

// ======================================================
// EMAIL
// ======================================================

async function enviarCorreo({
  to,
  clienteNombre,
  numeroFactura,
  numeroAutorizacion,
  xmlFirmado,
}) {
  if (
    !to ||
    !process.env.GMAIL_USER ||
    !process.env.GMAIL_APP_PASSWORD
  ) {
    return false;
  }

  const transporter =
    nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: {
        user:
          process.env.GMAIL_USER,
        pass:
          process.env.GMAIL_APP_PASSWORD,
      },
    });

  await transporter.sendMail({
    from: `"Casa Musical Buena Melodía J&G" <${process.env.GMAIL_USER}>`,
    to,
    subject: `Factura electrónica ${numeroFactura}`,
    html: `
      <p>Estimado/a <b>${clienteNombre ?? 'Cliente'}</b></p>
      <p>Adjunto encontrará su comprobante autorizado.</p>
    `,
    attachments: [
      {
        filename: `Factura-${numeroFactura}.xml`,
        content: xmlFirmado,
        contentType:
          'application/xml',
      },
    ],
  });

  return true;
}

// ======================================================
// ENDPOINT PRINCIPAL
// ======================================================

app.post(
  '/procesar-factura',
  async (req, res) => {
    try {
      const {
        xml,
        certBase64,
        certPassword,
        ambiente,
        claveAcceso,
        email,
        clienteNombre,
        numeroFactura,
      } = req.body;

      if (
        !xml ||
        !certBase64 ||
        !certPassword ||
        !ambiente ||
        !claveAcceso
      ) {
        return res.status(400).json({
          ok: false,
          error: 'Faltan parámetros',
        });
      }

      const xmlLimpio =
        limpiarXml(xml);

      const diagnosticoXml =
        diagnosticarXml(xmlLimpio);

      if (!diagnosticoXml.ok) {
        return res.json({
          ok: false,
          estado: 'XML_INVALIDO',
          error:
            'El XML generado no cumple las condiciones necesarias para firmarse y enviarse al SRI.',
          mensajes:
            diagnosticoXml.errores.map(
              (mensaje) => ({
                tipo: 'ERROR',
                identificador: 'XML',
                mensaje,
              })
            ),
          diagnosticoXml:
            diagnosticoXml.resumen,
        });
      }

      const p12Buffer =
        Buffer.from(
          certBase64,
          'base64'
        );

      const rucXml = getTag(
        xmlLimpio,
        'ruc'
      );

      let certInfo;

      try {
        certInfo =
          extraerCertificado(
            p12Buffer,
            certPassword
          );
      } catch (error) {
        const mensaje =
          error.message ??
          'No se pudo validar el archivo .p12.';

        console.error(
          'Certificado rechazado:',
          mensaje
        );

        return res.json({
          ok: false,
          estado:
            'CERTIFICADO_INVALIDO',
          error: mensaje,
          mensajes: [
            {
              tipo: 'ERROR',
              identificador:
                'CERTIFICADO',
              mensaje,
            },
          ],
          diagnosticoXml:
            diagnosticoXml.resumen,
        });
      }

      const certError =
        validarCertificadoContraXml(
          {
            xml: xmlLimpio,
            certInfo,
          }
        );

      console.log(
        'Procesando factura SRI',
        {
          version:
            SERVICE_VERSION,
          numeroFactura,
          ambiente,
          rucXml,
          claveAcceso: `${String(
            claveAcceso
          ).slice(
            0,
            10
          )}...${String(
            claveAcceso
          ).slice(-6)}`,
          xml:
            diagnosticoXml.resumen,
          certValidTo:
            certInfo.validTo
              .toISOString()
              .slice(0, 10),
          certSubject:
            certInfo.subject,
          certIndex:
            certInfo.certIndex,
        }
      );

      if (certError) {
        console.error(
          'Certificado inválido:',
          certError
        );

        return res.json({
          ok: false,
          estado:
            'CERTIFICADO_INVALIDO',
          error: certError,
          mensajes: [
            {
              tipo: 'ERROR',
              identificador:
                'CERTIFICADO',
              mensaje: certError,
            },
          ],
        });
      }

      // ======================================================
      // FIRMAR XML
      // ======================================================

      console.log(
        'Certificado seleccionado',
        {
          numeroFactura,
          totalCertsEnP12:
            certInfo.totalCertsEnP12,
          totalLlavesEnP12:
            certInfo.totalLlavesEnP12,
          certIndex:
            certInfo.certIndex,
          validFrom:
            certInfo.validFrom
              .toISOString()
              .slice(0, 10),
          validTo:
            certInfo.validTo
              .toISOString()
              .slice(0, 10),
        }
      );

      const xmlFirmado =
        await firmarXML(
          xmlLimpio,
          certInfo
        );

      if (
        !xmlFirmado.includes(
          '<ds:Signature'
        )
      ) {
        throw new Error(
          'La firma XAdES no fue insertada correctamente en el XML.'
        );
      }

      console.log(
        'XML firmado correctamente',
        {
          numeroFactura,
          contieneSignature:
            xmlFirmado.includes(
              '<ds:Signature'
            ),
          tieneNamespaceDs:
            xmlFirmado.includes(
              'xmlns:ds='
            ),
          tieneXades:
            xmlFirmado.includes(
              'xades'
            ),
          tieneX509:
            xmlFirmado.includes(
              'X509Certificate'
            ),
          firmadoSha256:
            hashXml(xmlFirmado),
        }
      );

      // ======================================================
      // ENVIAR A RECEPCIÓN SRI
      // ======================================================

      const recepcion =
        await enviarRecepcion(
          xmlFirmado,
          ambiente
        );

      console.log(
        'Respuesta recepción SRI',
        {
          numeroFactura,
          estado:
            recepcion.estado,
        }
      );

      if (
        recepcion.estado !==
        'RECIBIDA'
      ) {
        return res.json({
          ok: false,
          estado: 'DEVUELTA',
          error:
            'SRI no recibió el comprobante',
          mensajes:
            recepcion.mensajes
              .length > 0
              ? recepcion.mensajes
              : [
                  {
                    tipo: 'ERROR',
                    identificador:
                      'RECEPCION',
                    mensaje:
                      recepcion.raw.substring(
                        0,
                        500
                      ),
                  },
                ],
          diagnosticoXml:
            diagnosticoXml.resumen,
        });
      }

      // ======================================================
      // CONSULTAR AUTORIZACIÓN
      // ======================================================

      await new Promise((r) =>
        setTimeout(r, 2000)
      );

      const autorizacion =
        await consultarAutorizacion(
          claveAcceso,
          ambiente
        );

      console.log(
        'Respuesta autorización SRI',
        {
          numeroFactura,
          estado:
            autorizacion.estado,
          mensajes:
            autorizacion.mensajes,
        }
      );

      if (
        autorizacion.estado !==
        'AUTORIZADO'
      ) {
        return res.json({
          ok: false,
          estado:
            autorizacion.estado,
          error:
            autorizacion
              .mensajes?.[0]
              ?.mensaje ??
            'SRI no autorizó el comprobante',
          mensajes:
            autorizacion.mensajes,
          diagnosticoXml:
            diagnosticoXml.resumen,
        });
      }

      // ======================================================
      // ENVIAR EMAIL
      // ======================================================

      let correoEnviado =
        false;

      try {
        correoEnviado =
          await enviarCorreo({
            to: email,
            clienteNombre,
            numeroFactura,
            numeroAutorizacion:
              autorizacion.numeroAutorizacion,
            xmlFirmado,
          });
      } catch (e) {
        console.error(
          'Error enviando correo:',
          e.message
        );
      }

      // ======================================================
      // RESPUESTA FINAL
      // ======================================================

      return res.json({
        ok: true,
        estado: 'AUTORIZADO',
        numeroAutorizacion:
          autorizacion.numeroAutorizacion,
        fechaAutorizacion:
          autorizacion.fechaAutorizacion,
        mensajes:
          autorizacion.mensajes,
        xmlFirmado,
        correoEnviado,
      });

    } catch (err) {

      console.error(
        'Error procesando factura:',
        err
      );

      return res.status(500).json({
        ok: false,
        error:
          err.message ??
          'Error interno',
      });

    }
  }
);

// ======================================================
// HEALTHCHECK
// ======================================================

app.get('/', (_req, res) =>
  res.json({
    ok: true,
    service:
      'bm-sri-signer',
    version:
      SERVICE_VERSION,
  })
);

// ======================================================
// START SERVER
// ======================================================

app.listen(PORT, () =>
  console.log(
    `SRI Signer corriendo en puerto ${PORT}`
  )
);
