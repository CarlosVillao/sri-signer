import express from 'express';
import cors from 'cors';
import forge from 'node-forge';
import { SignedXml } from 'xml-crypto';
import { DOMParser } from 'xmldom';
import axios from 'axios';
import nodemailer from 'nodemailer';

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 3000;

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

// =============== FIRMADO XAdES-BES ===============
function firmarXML(xmlString, p12Buffer, password) {
  // 1. Cargar el .p12
  const p12Asn1 = forge.asn1.fromDer(p12Buffer.toString('binary'));
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);

  // 2. Extraer clave privada y certificado
  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
  const privateKey = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag][0].key;
  const certificate = certBags[forge.pki.oids.certBag][0].cert;

  const privateKeyPem = forge.pki.privateKeyToPem(privateKey);
  const certPem = forge.pki.certificateToPem(certificate);

  // 3. Firmar con xml-crypto (XAdES-BES simplificado)
  const sig = new SignedXml({
    privateKey: privateKeyPem,
    publicCert: certPem,
    signatureAlgorithm: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    canonicalizationAlgorithm: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
  });

  sig.addReference({
    xpath: "//*[local-name(.)='factura']",
    digestAlgorithm: 'http://www.w3.org/2000/09/xmldsig#sha1',
    transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature'],
  });

  sig.computeSignature(xmlString, {
    location: { reference: "//*[local-name(.)='factura']", action: 'append' },
  });

  return sig.getSignedXml();
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
  const res = await axios.post(url, soap, {
    headers: { 'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': '' },
    timeout: 30000,
  });
  const estadoMatch = res.data.match(/<estado>(.*?)<\/estado>/);
  return { estado: estadoMatch?.[1] ?? 'DESCONOCIDO', raw: res.data };
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
  const mensajes = [];
  const msgNodes = doc.getElementsByTagName('mensaje');
  for (let i = 0; i < msgNodes.length; i++) {
    mensajes.push({
      identificador: msgNodes[i].getElementsByTagName('identificador')[0]?.textContent,
      mensaje: msgNodes[i].getElementsByTagName('mensaje')[0]?.textContent,
      tipo: msgNodes[i].getElementsByTagName('tipo')[0]?.textContent,
    });
  }

  return { estado, numeroAutorizacion: numAut, fechaAutorizacion: fechaAut, mensajes };
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

    const p12Buffer = Buffer.from(certBase64, 'base64');

    // 1. Firmar
    const xmlFirmado = firmarXML(xml, p12Buffer, certPassword);

    // 2. Enviar a recepción
    const recepcion = await enviarRecepcion(xmlFirmado, ambiente);
    if (recepcion.estado !== 'RECIBIDA') {
      return res.json({ ok: false, estado: 'DEVUELTA', error: 'SRI no recibió el comprobante', mensajes: [{ raw: recepcion.raw.substring(0, 500) }] });
    }

    // 3. Esperar 2s y consultar autorización
    await new Promise(r => setTimeout(r, 2000));
    const autorizacion = await consultarAutorizacion(claveAcceso, ambiente);

    if (autorizacion.estado !== 'AUTORIZADO') {
      return res.json({ ok: false, estado: autorizacion.estado, mensajes: autorizacion.mensajes });
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

app.get('/', (_req, res) => res.json({ ok: true, service: 'bm-sri-signer', version: '1.0.0' }));

app.listen(PORT, () => console.log(`SRI Signer corriendo en puerto ${PORT}`));
