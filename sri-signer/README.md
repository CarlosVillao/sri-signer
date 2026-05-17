# BM SRI Signer para Railway

Microservicio Node.js para firmar facturas electrónicas Ecuador con XAdES-BES, enviarlas al SRI y devolver el XML firmado/autorizado. Está preparado para Railway con diagnósticos claros de XML, certificado y firma.

## Requisitos

- Node.js 20 o superior.
- Certificado `.p12/.pfx` vigente cargado desde la app principal; **no se guarda en Railway**.
- Variable `SRI_SIGNER_URL` en la app principal apuntando a la URL pública de Railway.

## Desplegar en Railway

1. Sube esta carpeta `sri-signer/` a un repositorio nuevo de GitHub.
2. En Railway: **New Project → Deploy from GitHub repo**.
3. Railway detectará Node.js y ejecutará `npm install` + `npm start`.
4. En **Settings → Networking**, genera un dominio público.
5. Abre la URL raíz. Debe responder algo como:

```json
{ "ok": true, "service": "bm-sri-signer", "version": "1.0.4-railway-stable-sri" }
```

## Variables de entorno opcionales

Solo son necesarias si quieres que este servicio envíe el XML autorizado por correo:

| Variable | Descripción |
|---|---|
| `GMAIL_USER` | Correo Gmail remitente |
| `GMAIL_APP_PASSWORD` | Contraseña de aplicación de Gmail, no la contraseña normal |
| `PORT` | Railway normalmente lo define automáticamente; puedes dejarlo vacío |

## Endpoint principal

`POST /procesar-factura`

```json
{
  "xml": "<?xml version=\"1.0\" encoding=\"UTF-8\"?><factura id=\"comprobante\" version=\"1.1.0\">...</factura>",
  "certBase64": "BASE64_DEL_P12",
  "certPassword": "CLAVE_DEL_P12",
  "ambiente": "1",
  "claveAcceso": "49_DIGITOS",
  "email": "cliente@correo.com",
  "clienteNombre": "Juan Pérez",
  "numeroFactura": "001-001-000000001"
}
```

## Qué valida antes de enviar al SRI

- XML bien formado.
- `<factura id="comprobante" version="1.1.0">`.
- Sin firma previa y sin namespaces antes de firmar.
- `ambiente`, RUC, establecimiento, punto de emisión, secuencial y clave de acceso.
- Dígito verificador módulo 11 de la clave de acceso.
- Contraseña del `.p12`.
- Certificado vigente y no vencido.
- Certificado correspondiente al RUC/cedula del XML.
- XML firmado con `ds:Signature`, `ds:SignedInfo`, `ds:SignatureValue`, `ds:X509Certificate` y `xades:SignedProperties`.

Si algo falla, responde con `estado`, `error`, `mensajes`, `diagnosticoXml` y, cuando aplique, `diagnosticoFirmado` para saber exactamente si el problema está en el XML, el certificado, la firma o la respuesta del SRI.

## Importante

- Usa `ambiente: "1"` para pruebas y `ambiente: "2"` para producción.
- La clave de acceso debe pertenecer al mismo ambiente que el XML.
- Si Railway muestra una versión distinta a `1.0.4-railway-stable-sri`, no está corriendo este paquete actualizado.
