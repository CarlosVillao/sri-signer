import express from 'express';
import cors from 'cors';
import axios from 'axios';
import nodemailer from 'nodemailer';
import forge from 'node-forge';
import { XMLValidator } from 'fast-xml-parser';
import { createHash } from 'crypto';
import fs from 'fs';
import { DOMParser } from '@xmldom/xmldom';
import pkg from 'ec-sri-invoice-signer';

const { SriInvoiceSigner } = pkg;

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 3000;
const SERVICE_VERSION = '1.0.3-sri-xml-diagnostics';

// URLs SRI Ecuador
const SRI_URLS = {
  '1': { // Pruebas
    recepcion: 'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl',
    autorizacion: 'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl',
  },
  '2': { // Producción
    recepcion: 'https://cel.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl',
    autorizacion: 'https://cel.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl',
  },
};

// =============== SELECCIÓN DE CERTIFICADO VIGENTE ===============
// Algunos .p12 (como los renovados por el Banco Central del Ecuador) contienen
// MÁS DE UN certificado de firma: el viejo vencido y el nuevo vigente. La librería
// ec-sri-invoice-signer toma siempre certBag[0], que suele ser el vencido.
// Esta función reconstruye un .p12 limpio con SOLO el certificado vigente y su
// llave privada correspondiente, para que el firmador use el correcto.
function prepararP12Vigente(p12Buffer, password) {
  const p12Asn1 = forge.asn1.fromDer(p12Buffer.toString('binary'));
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);

  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] || [];

  const now = new Date();
  // Filtrar solo certificados de firma vigentes (no CAs intermedias/raíz, no vencidos).
  const candidatos = certBags
    .map((b) => b.cert)
    .filter((c) => c && c.validity.notBefore <= now && c.validity.notAfter > now)
    .filter((c) => {
      // Excluir certificados de CA (Authority): los certificados de firma personal
      // tienen el shortName "CN" con el nombre de la persona y NO son CA.
      const bc = c.getExtension && c.getExtension('basicConstraints');
      return !(bc && bc.cA);
    })
    // Más reciente primero
    .sort((a, b) => b.validity.notAfter - a.validity.notAfter);

  if (candidatos.length === 0) {
    throw new Error('El .p12 no contiene ningún certificado de firma vigente. Todos están vencidos o son sólo CAs.');
  }
  const certVigente = candidatos[0];

  // Buscar la llave privada que coincida con la clave pública de ese certificado.
  let privateKey = null;
  for (const kb of keyBags) {
    if (!kb.key) continue;
    try {
      const pubFromKey = forge.pki.setRsaPublicKey(kb.key.n, kb.key.e);
      if (forge.pki.publicKeyToPem(pubFromKey) === forge.pki.publicKeyToPem(certVigente.publicKey)) {
        privateKey = kb.key;
        break;
      }
    } catch (_) { /* ignore */ }
  }
  if (!privateKey) {
    // Fallback: si solo hay una llave, asumirla
    if (keyBags.length === 1 && keyBags[0].key) privateKey = keyBags[0].key;
    else throw new Error('No se encontró la llave privada del certificado vigente dentro del .p12.');
  }

  // Reconstruir un PKCS#12 con la cadena completa de certificados.
// Algunos validadores del SRI necesitan también los certificados
// intermedios y raíz para reconocer correctamente la firma digital.

const cadenaCompleta = certBags
  .map((b) => b.cert)
  .filter(Boolean);

const newP12Asn1 = forge.pkcs12.toPkcs12Asn1(
  privateKey,
  cadenaCompleta,
  password,
  {
    algorithm: '3des',
    friendlyName: 'firma-vigente',
  }
);
  const newP12Der = forge.asn1.toDer(newP12Asn1).getBytes();
  return {
    buffer: Buffer.from(newP12Der, 'binary'),
    certVigente,
  };
}

// =============== FIRMADO XAdES-BES REAL ===============
async function firmarXML(xmlString, p12Buffer, password) {

  const signer = new SriInvoiceSigner(
    p12Buffer,
    password
  );

  const xmlFirmado = await signer.sign(
    xmlString
  );

  fs.writeFileSync(
    './debug-firmado.xml',
    xmlFirmado
  );

  return xmlFirmado;
}

function getTag(xml, tagName) {
  return xml.match(new RegExp(`<${tagName}>(.*?)</${tagName}>`))?.[1]?.trim() ?? null;
}

function hashXml(xml) {
  return createHash('sha256').update(xml, 'utf8').digest('hex');
}

function limpiarXml(xml) {
  return String(xml ?? '').replace(/^\uFEFF/, '').trim();
}

function diagnosticarXml(xml) {
  const limpio = limpiarXml(xml);
  const validation = XMLValidator.validate(limpio);
  const namespaces = limpio.match(/\sxmlns(?::\w+)?=/g) ?? [];
  const ambiente = getTag(limpio, 'ambiente');
  const clave = getTag(limpio, 'claveAcceso');
  const ruc = getTag(limpio, 'ruc');

  const errores = [];
  if (validation !== true) errores.push(`XML mal formado: ${validation.err?.msg ?? 'error no especificado'}`);
  if (namespaces.length > 0) errores.push(`El XML sin firmar no debe traer namespaces (${namespaces.join(', ')}).`);
  if (clave && clave.length !== 49) errores.push('La clave de acceso debe tener 49 dígitos.');
  if (clave && ambiente && clave.slice(23, 24) !== ambiente) errores.push(`La clave tiene ambiente ${clave.slice(23, 24)} pero el XML ambiente ${ambiente}.`);

  return {
    ok: errores.length === 0,
    errores,
    resumen: {
      sha256: hashXml(limpio),
      longitud: Buffer.byteLength(limpio, 'utf8'),
      ruc,
      ambiente,
      claveAcceso: clave ? `${clave.slice(0, 10)}...${clave.slice(-6)}` : null,
      secuencial: getTag(limpio, 'secuencial'),
      total: getTag(limpio, 'importeTotal'),
      namespacesDetectados: namespaces.length,
    },
  };
}

function extraerCertificado(p12Buffer, password) {
  const p12Asn1 = forge.asn1.fromDer(p12Buffer.toString('binary'));
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
  const now = new Date();
  // Elegir el mismo certificado que usaremos para firmar (vigente y no CA), no certBag[0].
  const cert = certBags
    .map((b) => b.cert)
    .filter((c) => c)
    .filter((c) => {
      const bc = c.getExtension && c.getExtension('basicConstraints');
      return !(bc && bc.cA);
    })
    .filter((c) => c.validity.notBefore <= now && c.validity.notAfter > now)
    .sort((a, b) => b.validity.notAfter - a.validity.notAfter)[0]
    || certBags[0]?.cert;
  if (!cert) throw new Error('El archivo .p12 no contiene un certificado X509 válido.');

  const subject = cert.subject.attributes.map((a) => `${a.shortName || a.name}=${a.value}`).join(' | ');
  const issuer = cert.issuer.attributes.map((a) => `${a.shortName || a.name}=${a.value}`).join(' | ');
  const subjectValues = cert.subject.attributes.map((a) => String(a.value ?? ''));
  const extensionValues = (cert.extensions || []).flatMap((ext) => [
    String(ext.value ?? ''),
    ...((ext.altNames || []).map((alt) => String(alt.value ?? ''))),
  ]);

  return {
    subject,
    issuer,
    values: [...subjectValues, ...extensionValues],
    validFrom: cert.validity.notBefore,
    validTo: cert.validity.notAfter,
    totalCertsEnP12: certBags.length,
    nowUtc: now.toISOString(),
  };
}

function validarCertificadoContraXml({ xml, certInfo }) {
  const rucXml = getTag(xml, 'ruc');
  const ambienteXml = getTag(xml, 'ambiente');
  const claveXml = getTag(xml, 'claveAcceso');
  const now = new Date();

  if (certInfo.validTo < now) {
    return `El certificado .p12 está vencido desde ${certInfo.validTo.toISOString().slice(0, 10)}. Sube una firma electrónica vigente.`;
  }

  if (certInfo.validFrom > now) {
    return `El certificado .p12 todavía no está vigente. Inicia el ${certInfo.validFrom.toISOString().slice(0, 10)}.`;
  }

  if (rucXml) {
    const cedulaDelRuc = rucXml.slice(0, 10);
    const perteneceAlRuc = certInfo.values.some((value) => value.includes(rucXml) || value.includes(cedulaDelRuc));
    if (!perteneceAlRuc) {
      return `El certificado .p12 no corresponde al RUC ${rucXml}. Certificado detectado: ${certInfo.subject}. Sube la firma emitida para ese RUC.`;
    }
  }

  if (claveXml?.length === 49 && ambienteXml && claveXml.slice(23, 24) !== ambienteXml) {
    return `La clave de acceso tiene ambiente ${claveXml.slice(23, 24)}, pero el XML tiene ambiente ${ambienteXml}.`;
  }

  return null;
}

// =============== ENVÍO SOAP AL SRI ===============
async function enviarRecepcion(xmlFirmado, ambiente) {

const xmlSinDeclaracion = xmlFirmado.replace(
  /<\?xml.*?\?>/,
  ''
).trim();
  
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
    SRI_URLS[ambiente].recepcion.replace(
      '?wsdl',
      ''
    );

  console.log('Enviando a recepcion SRI...');

  try {

    const res = await axios.post(
      url,
      soap,
      {
        headers: {
          'Content-Type': 'text/xml; charset=utf-8',
          SOAPAction: '',
      },

        timeout: 60000,
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
      }
    );

    console.log(
      'SRI recepcion respondio'
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
        extraerMensajesSri(res.data)
    };

  } catch (error) {

    console.error(
      'ERROR SRI RECEPCION:',
      error.code,
      error.message
    );

    // SI EL SRI RESPONDIÓ CON XML DE ERROR
    if (error.response?.data) {

      console.log('SOAP ERROR DEL SRI:');
      console.log(error.response.data);

      return {
        estado: 'DEVUELTA',
        raw: error.response.data,
        mensajes: extraerMensajesSri(error.response.data)
      };
    }

    // SI FUE ERROR DE RED/TLS
    return {
      estado: 'ERROR_RED',
      raw: error.message,
      mensajes: [
        {
          identificador: error.code || 'NETWORK',
          mensaje: error.message,
          tipo: 'ERROR'
        }
      ]
    };
  }
}

function extraerMensajesSri(rawXml) {
  const doc = new DOMParser().parseFromString(rawXml, 'text/xml');
  const nodes = Array.from(doc.getElementsByTagName('mensaje'));
  return nodes
    .map((node) => ({
      identificador: node.getElementsByTagName('identificador')[0]?.textContent ?? null,
      mensaje: node.getElementsByTagName('mensaje')[0]?.textContent ?? node.textContent?.trim() ?? null,
      informacionAdicional: node.getElementsByTagName('informacionAdicional')[0]?.textContent ?? null,
      tipo: node.getElementsByTagName('tipo')[0]?.textContent ?? null,
    }))
    .filter((m) => m.identificador || m.mensaje || m.informacionAdicional || m.tipo);
}

async function consultarAutorizacion(claveAcceso, ambiente) {
  const soap = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ec="http://ec.gob.sri.ws.autorizacion">
  <soapenv:Body>
    <ec:autorizacionComprobante>
      <claveAccesoComprobante>${claveAcceso}</claveAccesoComprobante>
    </ec:autorizacionComprobante>
  </soapenv:Body>
</soapenv:Envelope>`;

  const url = SRI_URLS[ambiente].autorizacion.replace('?wsdl', '');
  const res = await axios.post(url, soap, {
    headers: { 'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': '' },
    timeout: 30000,
  });

  const doc = new DOMParser().parseFromString(res.data, 'text/xml');
  const estado = doc.getElementsByTagName('estado')[0]?.textContent ?? 'NO_AUTORIZADO';
  const numAut = doc.getElementsByTagName('numeroAutorizacion')[0]?.textContent ?? null;
  const fechaAut = doc.getElementsByTagName('fechaAutorizacion')[0]?.textContent ?? null;
  const mensajes = extraerMensajesSri(res.data);

  return { estado, numeroAutorizacion: numAut, fechaAutorizacion: fechaAut, mensajes, raw: res.data };
}

// =============== ENVÍO DE CORREO (Gmail SMTP) ===============
async function enviarCorreo({ to, clienteNombre, numeroFactura, numeroAutorizacion, xmlFirmado }) {
  if (!to || !process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) return false;

  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD },
  });

  await transporter.sendMail({
    from: `"Casa Musical Buena Melodía J&G" <${process.env.GMAIL_USER}>`,
    to,
    subject: `Factura electrónica ${numeroFactura} - Buena Melodía J&G`,
    html: `
      <p>Estimado/a <b>${clienteNombre ?? 'Cliente'}</b>,</p>
      <p>Adjunto encontrará el comprobante electrónico autorizado por el SRI.</p>
      <ul>
        <li><b>Factura:</b> ${numeroFactura}</li>
        <li><b>N° Autorización SRI:</b> ${numeroAutorizacion}</li>
      </ul>
      <p>Gracias por su compra.</p>
      <p style="color:#888;font-size:12px">Casa Musical Buena Melodía J&amp;G</p>
    `,
    attachments: [
      { filename: `Factura-${numeroFactura}.xml`, content: xmlFirmado, contentType: 'application/xml' },
    ],
  });
  return true;
}

// =============== ENDPOINT PRINCIPAL ===============
app.post('/procesar-factura', async (req, res) => {
  try {
    const { xml, certBase64, certPassword, ambiente, claveAcceso, email, clienteNombre, numeroFactura } = req.body;

    if (!xml || !certBase64 || !certPassword || !ambiente || !claveAcceso) {
      return res.status(400).json({ ok: false, error: 'Faltan parámetros' });
    }

    const xmlLimpio = limpiarXml(xml);
    const diagnosticoXml = diagnosticarXml(xmlLimpio);
    if (!diagnosticoXml.ok) {
      return res.json({
        ok: false,
        estado: 'XML_INVALIDO',
        error: 'El XML generado no cumple las condiciones necesarias para firmarse y enviarse al SRI.',
        mensajes: diagnosticoXml.errores.map((mensaje) => ({ tipo: 'ERROR', identificador: 'XML', mensaje })),
        diagnosticoXml: diagnosticoXml.resumen,
      });
    }

    const p12Buffer = Buffer.from(certBase64, 'base64');
    const rucXml = getTag(xmlLimpio, 'ruc');
    const certInfo = extraerCertificado(p12Buffer, certPassword);
    const certError = validarCertificadoContraXml({ xml: xmlLimpio, certInfo });
    console.log('Procesando factura SRI', {
      version: SERVICE_VERSION,
      numeroFactura,
      ambiente,
      rucXml,
      claveAcceso: `${String(claveAcceso).slice(0, 10)}...${String(claveAcceso).slice(-6)}`,
      xml: diagnosticoXml.resumen,
      certValidTo: certInfo.validTo.toISOString().slice(0, 10),
      certSubject: certInfo.subject,
    });

    if (certError) {
      console.error('Certificado rechazado antes de enviar al SRI:', certError);
      return res.json({ ok: false, estado: 'CERTIFICADO_INVALIDO', error: certError, mensajes: [{ tipo: 'ERROR', identificador: 'CERTIFICADO', mensaje: certError }] });
    }

    // 1. Firmar (usar p12 saneado: SOLO el certificado vigente + su llave)
    const { buffer: p12Vigente, certVigente } = prepararP12Vigente(p12Buffer, certPassword);
    console.log('Certificado seleccionado para firmar', {
      numeroFactura,
      totalCertsEnP12: certInfo.totalCertsEnP12,
      validFrom: certVigente.validity.notBefore.toISOString().slice(0, 10),
      validTo: certVigente.validity.notAfter.toISOString().slice(0, 10),
    });
    const xmlFirmado = await firmarXML(xmlLimpio, p12Vigente, certPassword);
    if (!xmlFirmado.includes('<ds:Signature')) {
      throw new Error('La firma XAdES no fue insertada correctamente en el XML.');
    }
    console.log('XML firmado correctamente', {
      numeroFactura,
      contieneSignature: xmlFirmado.includes('<ds:Signature'),
      tieneNamespaceDs: xmlFirmado.includes('xmlns:ds='),
      tieneXades: xmlFirmado.includes('xades'),
      tieneX509: xmlFirmado.includes('X509Certificate'),
      firmadoSha256: hashXml(xmlFirmado)
    });
    fs.writeFileSync('./ultimo-firmado.xml', xmlFirmado);

    // 2. Enviar a recepción
    const recepcion = await enviarRecepcion(xmlFirmado, ambiente);
    console.log('Respuesta recepción SRI', { numeroFactura, estado: recepcion.estado });
    if (recepcion.estado !== 'RECIBIDA') {
      return res.json({
        ok: false,
        estado: 'DEVUELTA',
        error: 'SRI no recibió el comprobante',
        mensajes: recepcion.mensajes.length > 0 ? recepcion.mensajes : [{ tipo: 'ERROR', identificador: 'RECEPCION', mensaje: recepcion.raw.substring(0, 500) }],
        diagnosticoXml: diagnosticoXml.resumen,
      });
    }

    // 3. Esperar 2s y consultar autorización
    await new Promise(r => setTimeout(r, 2000));
    const autorizacion = await consultarAutorizacion(claveAcceso, ambiente);
    console.log('Respuesta autorización SRI', { numeroFactura, estado: autorizacion.estado, mensajes: autorizacion.mensajes });

    if (autorizacion.estado !== 'AUTORIZADO') {
      return res.json({
        ok: false,
        estado: autorizacion.estado,
        error: autorizacion.mensajes[0]?.mensaje ?? 'SRI no autorizó el comprobante',
        mensajes: autorizacion.mensajes,
        diagnosticoXml: diagnosticoXml.resumen,
      });
    }

    // 4. Enviar correo si hay destinatario
    let correoEnviado = false;
    try {
      correoEnviado = await enviarCorreo({ to: email, clienteNombre, numeroFactura, numeroAutorizacion: autorizacion.numeroAutorizacion, xmlFirmado });
    } catch (e) {
      console.error('Error enviando correo:', e.message);
    }

    res.json({
      ok: true,
      estado: 'AUTORIZADO',
      numeroAutorizacion: autorizacion.numeroAutorizacion,
      fechaAutorizacion: autorizacion.fechaAutorizacion,
      mensajes: autorizacion.mensajes,
      xmlFirmado,
      correoEnviado,
    });
  } catch (err) {
    console.error('Error procesando factura:', err);
    res.status(500).json({ ok: false, error: err.message ?? 'Error interno' });
  }
});

app.get('/', (_req, res) => res.json({ ok: true, service: 'bm-sri-signer', version: SERVICE_VERSION }));

app.listen(PORT, () => console.log(`SRI Signer corriendo en puerto ${PORT}`));
