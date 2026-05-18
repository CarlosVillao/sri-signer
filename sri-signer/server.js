import express from 'express';
import cors from 'cors';
import { DOMParser } from '@xmldom/xmldom';
import axios from 'axios';
import forge from 'node-forge';
import { XMLValidator } from 'fast-xml-parser';
import { createHash } from 'crypto';
import { signInvoiceXml } from 'ec-sri-invoice-signer';
import https from 'https'; 
import dns from 'dns';
import nodemailer from 'nodemailer';

dns.setDefaultResultOrder('ipv4first');

process.env.NODE_OPTIONS = '--dns-result-order=ipv4first';

const app = express();
app.use(cors());
app.use(express.json({ limit: '15mb' }));

const PORT = process.env.PORT || 3000;
const SERVICE_VERSION = '1.0.4-railway-stable-sri';
const cacheEnvios = global.cacheEnvios || (global.cacheEnvios = new Map());

setInterval(() => {
  const now = Date.now();
  const TTL = 10 * 60 * 1000;

  for (const [key, value] of cacheEnvios.entries()) {
    if (!value?.tiempo) continue; // 👈 protección

    if (now - value.tiempo > TTL) {
      cacheEnvios.delete(key);
    }
  }
}, 5 * 60 * 1000);

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
      // Excluir certificados CA
      const bc = c.getExtension && c.getExtension('basicConstraints');
      if (bc && bc.cA) return false;

      // Verificar que el certificado sea de FIRMA DIGITAL
      const keyUsage = c.getExtension && c.getExtension('keyUsage');

      console.log('KEY USAGE', {
        digitalSignature: keyUsage?.digitalSignature,
        nonRepudiation: keyUsage?.nonRepudiation,
        keyEncipherment: keyUsage?.keyEncipherment,
      });

      const permiteFirma =
        keyUsage &&
        (
          keyUsage.digitalSignature ||
          keyUsage.nonRepudiation
        );

      return permiteFirma;
    }).sort((a, b) => b.validity.notAfter - a.validity.notAfter);

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

  // Reconstruir un PKCS#12 con SOLO el certificado vigente + su llave.
  const newP12Asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, [certVigente], password, {
    algorithm: '3des',
    friendlyName: 'firma-vigente',
  });
  const newP12Der = forge.asn1.toDer(newP12Asn1).getBytes();
  return {
    buffer: Buffer.from(newP12Der, 'binary'),
    certVigente,
  };
}

// =============== FIRMADO XAdES-BES ===============
function firmarXML(xmlString, p12Buffer, password) {
  // Firma XAdES-BES estricta para comprobantes SRI Ecuador.
  // Si la contraseña desencriptada fuera incorrecta, esta función falla antes de enviar al SRI.
  return signInvoiceXml(xmlString, p12Buffer, { pkcs12Password: password });
}

function getTag(xml, tagName) {
  return xml.match(new RegExp(`<${tagName}>([\\s\\S]*?)</${tagName}>`, 'i'))?.[1]?.trim() ?? null;
}

function hashXml(xml) {
  return createHash('sha256').update(xml, 'utf8').digest('hex');
}

function limpiarXml(xml) {
  return String(xml ?? '')
    .replace(/^\uFEFF/, '')
    .replace(/\r\n/g, '\n')
    .trim();
}

function decodificarBase64(valor) {
  const limpio = String(valor ?? '')
    .replace(/^data:.*?;base64,/i, '')
    .replace(/\s+/g, '');
  if (!limpio) throw new Error('El certificado llegó vacío.');
  return Buffer.from(limpio, 'base64');
}

function normalizarAmbiente(ambiente) {
  const valor = String(ambiente ?? '').trim();
  if (!['1', '2'].includes(valor)) {
    throw new Error('Ambiente SRI inválido. Use 1 para pruebas o 2 para producción.');
  }
  return valor;
}

function validarModulo11ClaveAcceso(clave) {
  if (!/^\d{49}$/.test(String(clave ?? ''))) return false;
  const digitos = clave.slice(0, 48).split('').reverse();
  let factor = 2;
  let suma = 0;
  for (const digito of digitos) {
    suma += Number(digito) * factor;
    factor = factor === 7 ? 2 : factor + 1;
  }
  const mod = suma % 11;
  const verificador = mod === 0 ? 0 : mod === 1 ? 1 : 11 - mod;
  return verificador === Number(clave[48]);
}

function diagnosticarXml(xml) {
  const limpio = limpiarXml(xml);
  const validation = XMLValidator.validate(limpio);
  const namespaces = limpio.match(/\sxmlns(?::\w+)?=/g) ?? [];
  const rootMatch = limpio.match(/<factura\s+([^>]*)>/i);
  const rootAttrs = rootMatch?.[1] ?? '';
  const tieneIdComprobante = /\s(?:id|Id)=['"]comprobante['"]/.test(` ${rootAttrs}`);
  const ambiente = getTag(limpio, 'ambiente');
  const clave = getTag(limpio, 'claveAcceso');
  const ruc = getTag(limpio, 'ruc');
  const estab = getTag(limpio, 'estab');
  const ptoEmi = getTag(limpio, 'ptoEmi');
  const secuencial = getTag(limpio, 'secuencial');
  const codDoc = getTag(limpio, 'codDoc');

  const errores = [];
  if (validation !== true) errores.push(`XML mal formado: ${validation.err?.msg ?? 'error no especificado'}`);
  if (!rootMatch) errores.push('El comprobante debe tener una etiqueta raíz <factura>.');
  if (!tieneIdComprobante) errores.push('La etiqueta <factura> debe tener id="comprobante" o Id="comprobante".');
  if (namespaces.length > 0) errores.push(`El XML sin firmar no debe traer namespaces (${namespaces.join(', ')}).`);
  if (limpio.includes('<ds:Signature') || limpio.includes('<Signature')) errores.push('El XML que llega al firmador ya está firmado; debe enviarse sin firma previa.');
  if (!['1', '2'].includes(String(ambiente))) errores.push('El campo <ambiente> debe ser 1 (pruebas) o 2 (producción).');
  if (!/^\d{13}$/.test(String(ruc ?? ''))) errores.push('El campo <ruc> debe tener 13 dígitos.');
  if (codDoc !== '01') errores.push('Este servicio está configurado para facturas SRI; <codDoc> debe ser 01.');
  if (!/^\d{3}$/.test(String(estab ?? ''))) errores.push('El campo <estab> debe tener 3 dígitos.');
  if (!/^\d{3}$/.test(String(ptoEmi ?? ''))) errores.push('El campo <ptoEmi> debe tener 3 dígitos.');
  if (!/^\d{9}$/.test(String(secuencial ?? ''))) errores.push('El campo <secuencial> debe tener 9 dígitos.');
  if (clave && !/^\d{49}$/.test(clave)) errores.push('La clave de acceso debe tener 49 dígitos numéricos.');
  if (clave && /^\d{49}$/.test(clave) && !validarModulo11ClaveAcceso(clave)) errores.push('El dígito verificador de la clave de acceso no es válido.');
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
      estab,
      ptoEmi,
      secuencial,
      total: getTag(limpio, 'importeTotal'),
      tieneIdComprobante,
      namespacesDetectados: namespaces.length,
      modulo11ClaveAccesoOk: clave ? validarModulo11ClaveAcceso(clave) : null,
    },
  };
}

function diagnosticarXmlFirmado(xmlFirmado) {
  const limpio = limpiarXml(xmlFirmado);
  const validation = XMLValidator.validate(limpio);
  const errores = [];
  if (validation !== true) errores.push(`XML firmado mal formado: ${validation.err?.msg ?? 'error no especificado'}`);
  const signatureCount = (limpio.match(/<ds:Signature\b/g) ?? []).length;
  if (signatureCount !== 1) errores.push(`El XML firmado debe contener exactamente una firma ds:Signature; contiene ${signatureCount}.`);
  if (!limpio.includes('URI="#comprobante"')) errores.push('La firma no referencia URI="#comprobante".');
  if (!limpio.includes('<ds:SignedInfo')) errores.push('La firma no contiene ds:SignedInfo.');
  if (!limpio.includes('<ds:SignatureValue')) errores.push('La firma no contiene ds:SignatureValue.');
  if (!limpio.includes('<ds:X509Certificate')) errores.push('La firma no contiene ds:X509Certificate.');
  if (!limpio.includes('<xades:SignedProperties')) errores.push('La firma no contiene xades:SignedProperties.');
  return { ok: errores.length === 0, errores, resumen: { sha256: hashXml(limpio), longitud: Buffer.byteLength(limpio, 'utf8'), signatureCount } };
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
  const xmlBase64 = Buffer.from(xmlFirmado, 'utf8').toString('base64');
  const soap = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ec="http://ec.gob.sri.ws.recepcion">
  <soapenv:Body>
    <ec:validarComprobante>
      <xml>${xmlBase64}</xml>
    </ec:validarComprobante>
  </soapenv:Body>
</soapenv:Envelope>`;

  const url = SRI_URLS[ambiente].recepcion.replace('?wsdl', '');
  const agent = new https.Agent({
    keepAlive: true,   // 🔥 CRÍTICO
    minVersion: 'TLSv1.2',
    rejectUnauthorized: false
  });

  const MAX_RETRIES = 3;
  const INITIAL_DELAY_MS = 2000;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      console.log(`[enviarRecepcion] Intento ${attempt}/${MAX_RETRIES} → ${url}`);
      const res = await axios.post(url, soap, {
        headers: {
          'Content-Type': 'text/xml; charset=utf-8',
          SOAPAction: '',
          'User-Agent': 'NodeJS-SRI-Client',
          Connection: 'close'
        },
        timeout: 120000,
        httpsAgent: agent,
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
        validateStatus: () => true
      });
      const estadoMatch = res.data.match(/<estado>(.*?)<\/estado>/);
      return { estado: estadoMatch?.[1] ?? 'DESCONOCIDO', raw: res.data, mensajes: extraerMensajesSri(res.data) };
    } catch (error) {
      const isConnectionError =
        error.code === 'ECONNRESET' ||
        error.code === 'ETIMEDOUT' ||
        error.code === 'ECONNREFUSED' ||
        error.code === 'ENOTFOUND';

      if (isConnectionError) {
        console.error(`[enviarRecepcion] Error de conexión intento ${attempt}/${MAX_RETRIES}: [${error.code}] ${error.message}`);
      } else {
        console.error(`[enviarRecepcion] Error intento ${attempt}/${MAX_RETRIES}: ${error.message}`);
      }

      if (attempt < MAX_RETRIES) {
        const delay = INITIAL_DELAY_MS * Math.pow(2, attempt - 1);
        console.log(`[enviarRecepcion] Reintentando en ${delay}ms...`);
        await new Promise(r => setTimeout(r, delay));
      } else {
        console.error(`[enviarRecepcion] Se agotaron los ${MAX_RETRIES} intentos. Último error: [${error.code ?? 'ERR'}] ${error.message}`);
        throw error;
      }
    }
  }
}

function extraerMensajesSri(rawXml) {
  const doc = new DOMParser().parseFromString(rawXml, 'text/xml');
  const nodes = Array.from(doc.getElementsByTagName('mensaje')).filter((node) =>
    node.getElementsByTagName('identificador').length > 0 || node.getElementsByTagName('informacionAdicional').length > 0
  );
  return nodes
    .map((node) => ({
      identificador: node.getElementsByTagName('identificador')[0]?.textContent ?? null,
      mensaje: Array.from(node.childNodes).find((child) => child.nodeName === 'mensaje')?.textContent?.trim() ?? null,
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
  const agent = new https.Agent({
    keepAlive: true,   // 🔥 CRÍTICO
    minVersion: 'TLSv1.2',
    rejectUnauthorized: false
  });

  const MAX_RETRIES = 3;
  const INITIAL_DELAY_MS = 2000;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      console.log(`[consultarAutorizacion] Intento ${attempt}/${MAX_RETRIES} → ${url}`);
      const res = await axios.post(url, soap, {
        headers: {
          'Content-Type': 'text/xml; charset=utf-8',
          SOAPAction: '',
          'User-Agent': 'NodeJS-SRI-Client',
          Connection: 'close'
        },
        timeout: 120000,
        httpsAgent: agent,
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
        validateStatus: () => true
      });

      const doc = new DOMParser().parseFromString(res.data, 'text/xml');
      const estado = doc.getElementsByTagName('estado')[0]?.textContent ?? 'NO_AUTORIZADO';
      const numAut = doc.getElementsByTagName('numeroAutorizacion')[0]?.textContent ?? null;
      const fechaAut = doc.getElementsByTagName('fechaAutorizacion')[0]?.textContent ?? null;
      const mensajes = extraerMensajesSri(res.data);

      return { estado, numeroAutorizacion: numAut, fechaAutorizacion: fechaAut, mensajes, raw: res.data };
    } catch (error) {
      const isConnectionError =
        error.code === 'ECONNRESET' ||
        error.code === 'ETIMEDOUT' ||
        error.code === 'ECONNREFUSED' ||
        error.code === 'ENOTFOUND';

      if (isConnectionError) {
        console.error(`[consultarAutorizacion] Error de conexión intento ${attempt}/${MAX_RETRIES}: [${error.code}] ${error.message}`);
      } else {
        console.error(`[consultarAutorizacion] Error intento ${attempt}/${MAX_RETRIES}: ${error.message}`);
      }

      if (attempt < MAX_RETRIES) {
        const delay = INITIAL_DELAY_MS * Math.pow(2, attempt - 1);
        console.log(`[consultarAutorizacion] Reintentando en ${delay}ms...`);
        await new Promise(r => setTimeout(r, delay));
      } else {
        console.error(`[consultarAutorizacion] Se agotaron los ${MAX_RETRIES} intentos. Último error: [${error.code ?? 'ERR'}] ${error.message}`);
        throw error;
      }
    }
  }
}

// =============== ENVÍO DE CORREO (Gmail SMTP) ===============
async function enviarCorreo({
  to,
  clienteNombre,
  numeroFactura,
  numeroAutorizacion,
  xmlFirmado
}) {
  if (!to || !process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
    return false;
  }

  const MAX_RETRIES = 3;
  const INITIAL_DELAY_MS = 2000;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const transporter = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 587,
        secure: false,
        auth: {
          user: process.env.GMAIL_USER,
          pass: process.env.GMAIL_APP_PASSWORD
        },
        tls: {
          rejectUnauthorized: false
        },
        connectionTimeout: 30000,
        greetingTimeout: 30000,
        socketTimeout: 30000
      });

      const info = await transporter.sendMail({
        from: `"Casa Musical Buena Melodía J&G" <${process.env.GMAIL_USER}>`,
        to,
        subject: `Factura electrónica ${numeroFactura} - SRI`,
        html: `
        <p>Estimado/a <b>${clienteNombre ?? 'Cliente'}</b>,</p>
        <p>Su factura <b>${numeroFactura}</b> ha sido autorizada por el SRI.</p>
        <p><b>N° Autorización:</b> ${numeroAutorizacion}</p>
      `,
        attachments: [
          {
            filename: `Factura-${numeroFactura}.xml`,
            content: xmlFirmado,
            contentType: 'application/xml'
          }
        ]
      });

      console.log(`Correo enviado correctamente en intento ${attempt}:`, info.messageId);
      return !!info.messageId;

    } catch (error) {
      const isConnectionError =
        error.code === 'ECONNREFUSED' ||
        error.code === 'ETIMEDOUT' ||
        error.code === 'ENOTFOUND' ||
        error.code === 'ECONNRESET' ||
        error.command === 'CONN';

      if (isConnectionError) {
        console.error(`ERROR GMAIL (conexión SMTP) intento ${attempt}/${MAX_RETRIES}: [${error.code ?? error.command}] ${error.message}`);
      } else {
        console.error(`ERROR GMAIL intento ${attempt}/${MAX_RETRIES}: ${error.message}`);
      }

      if (attempt < MAX_RETRIES) {
        const delay = INITIAL_DELAY_MS * Math.pow(2, attempt - 1);
        console.log(`Reintentando envío de correo en ${delay}ms...`);
        await new Promise(r => setTimeout(r, delay));
      } else {
        console.error(`ERROR GMAIL: Se agotaron los ${MAX_RETRIES} intentos. El correo no pudo enviarse.`);
      }
    }
  }

  return false;
}
// =============== ENDPOINT PRINCIPAL ===============
app.post('/procesar-factura', async (req, res) => {
  try {

    const { xml, certBase64, certPassword, ambiente, claveAcceso, email, clienteNombre, numeroFactura } = req.body;

    if (cacheEnvios.has(claveAcceso)) {
      return res.json({
        ok: false,
        estado: 'DUPLICADA',
        error: 'Esta factura ya fue procesada en este servidor'
      });
    }
    cacheEnvios.set(claveAcceso, {
      estado: 'PROCESANDO',
      tiempo: Date.now()
    });
    if (!xml || !certBase64 || !certPassword || !ambiente || !claveAcceso) {
      return res.status(400).json({ ok: false, error: 'Faltan parámetros' });
    }
    const ambienteSri = normalizarAmbiente(ambiente);

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

    const claveXml = getTag(xmlLimpio, 'claveAcceso');
    if (String(claveXml) !== String(claveAcceso)) {
      return res.json({
        ok: false,
        estado: 'XML_INVALIDO',
        error: 'La claveAcceso enviada en el request no coincide con la claveAcceso dentro del XML.',
        mensajes: [{ tipo: 'ERROR', identificador: 'XML', mensaje: 'claveAcceso del request y del XML no coinciden.' }],
        diagnosticoXml: diagnosticoXml.resumen,
      });
    }

    const p12Buffer = decodificarBase64(certBase64);
    const rucXml = getTag(xmlLimpio, 'ruc');
    const certInfo = extraerCertificado(p12Buffer, certPassword);
    const certError = validarCertificadoContraXml({ xml: xmlLimpio, certInfo });
    console.log('Procesando factura SRI', {
      version: SERVICE_VERSION,
      numeroFactura,
      ambiente: ambienteSri,
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
    const xmlFirmado = firmarXML(xmlLimpio, p12Vigente, certPassword);
    const diagnosticoFirmado = diagnosticarXmlFirmado(xmlFirmado);
    console.log('XML firmado correctamente', { numeroFactura, firmado: diagnosticoFirmado.resumen });
    if (!diagnosticoFirmado.ok) {
      return res.json({
        ok: false,
        estado: 'FIRMA_INVALIDA_LOCAL',
        error: 'El XML se firmó, pero no pasó la validación local mínima antes de enviarse al SRI.',
        mensajes: diagnosticoFirmado.errores.map((mensaje) => ({ tipo: 'ERROR', identificador: 'FIRMA_LOCAL', mensaje })),
        diagnosticoXml: diagnosticoXml.resumen,
        diagnosticoFirmado: diagnosticoFirmado.resumen,
      });
    }

    // 2. Enviar a recepción
    const recepcion = await enviarRecepcion(xmlFirmado, ambienteSri);
    if (recepcion.estado === 'RECIBIDA' && recepcion.mensajes.length === 0) {
      cacheEnvios.set(claveAcceso, {
        estado: 'ENVIADO_SRI',
        tiempo: cacheEnvios.get(claveAcceso)?.tiempo ?? Date.now()
      });
    }
    console.log('Respuesta recepción SRI', { numeroFactura, estado: recepcion.estado, mensajes: recepcion.mensajes });
    if (recepcion.estado !== 'RECIBIDA') {
      cacheEnvios.delete(claveAcceso);
      return res.json({
        ok: false,
        estado: 'DEVUELTA',
        error: 'SRI no recibió el comprobante',
        mensajes: recepcion.mensajes.length > 0 ? recepcion.mensajes : [{ tipo: 'ERROR', identificador: 'RECEPCION', mensaje: recepcion.raw.substring(0, 500) }],
        diagnosticoXml: diagnosticoXml.resumen,
        diagnosticoFirmado: diagnosticoFirmado.resumen,
      });
    }

    // 3. Esperar 2s y consultar autorización
    await new Promise(r => setTimeout(r, 2000));
    const autorizacion = await consultarAutorizacion(claveAcceso, ambienteSri);
    console.log('Respuesta autorización SRI', { numeroFactura, estado: autorizacion.estado, mensajes: autorizacion.mensajes });

    if (autorizacion.estado !== 'AUTORIZADO') {
      return res.json({
        ok: false,
        estado: autorizacion.estado,
        error: autorizacion.mensajes[0]?.mensaje ?? 'SRI no autorizó el comprobante',
        mensajes: autorizacion.mensajes,
        diagnosticoXml: diagnosticoXml.resumen,
        diagnosticoFirmado: diagnosticoFirmado.resumen,
      });
    }

    // 4. Responder al cliente inmediatamente; el correo se envía en segundo plano
    res.json({
      ok: true,
      estado: 'AUTORIZADO',
      numeroAutorizacion: autorizacion.numeroAutorizacion,
      fechaAutorizacion: autorizacion.fechaAutorizacion,
      mensajes: autorizacion.mensajes,
      xmlFirmado,
      diagnosticoXml: diagnosticoXml.resumen,
      diagnosticoFirmado: diagnosticoFirmado.resumen,
      correoEnviado: !!email,
    });

    // Enviar correo en segundo plano (no bloquea la respuesta)
    if (email) {
      enviarCorreo({ to: email, clienteNombre, numeroFactura, numeroAutorizacion: autorizacion.numeroAutorizacion, xmlFirmado })
        .then((enviado) => {
          console.log(`Correo background para factura ${numeroFactura}: ${enviado ? 'enviado' : 'fallido'}`);
        })
        .catch((e) => {
          console.error(`Error inesperado en envío background de correo para factura ${numeroFactura}:`, e.message);
        });
    }
  } catch (err) {
    console.error('Error procesando factura:', err);
    res.status(500).json({ ok: false, error: err.message ?? 'Error interno' });
  }
});

app.get('/', (_req, res) => res.json({ ok: true, service: 'bm-sri-signer', version: SERVICE_VERSION }));

app.listen(PORT, () => console.log(`SRI Signer corriendo en puerto ${PORT}`));
