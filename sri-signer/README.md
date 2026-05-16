# BM SRI Signer

Microservicio Node.js que firma comprobantes electrónicos (XAdES-BES), los envía al SRI Ecuador y notifica al cliente por correo. Diseñado para correr en Railway.

## Endpoint

`POST /procesar-factura`

Body JSON:
```json
{
  "xml": "<?xml version='1.0'?>...",
  "certBase64": "MIIK...",
  "certPassword": "tu-pwd-del-p12",
  "ambiente": "1",
  "claveAcceso": "49 dígitos",
  "email": "cliente@correo.com",
  "clienteNombre": "Juan Pérez",
  "numeroFactura": "001-001-000000001"
}
```

Respuesta exitosa:
```json
{
  "ok": true,
  "estado": "AUTORIZADO",
  "numeroAutorizacion": "...",
  "fechaAutorizacion": "...",
  "xmlFirmado": "<?xml...",
  "correoEnviado": true
}
```

El endpoint también valida antes de enviar al SRI que:

- La contraseña abre correctamente el `.p12`.
- El certificado está vigente.
- El certificado pertenece al mismo RUC del XML.

Si falla cualquiera de esas validaciones, responde `CERTIFICADO_INVALIDO` con el motivo exacto en vez de enviar una firma que el SRI rechazará como `FIRMA INVALIDA`.

## Despliegue en Railway — paso a paso

### 1. Sube esta carpeta a un repo NUEVO de GitHub

Descarga el código del proyecto Lovable, extrae **solo** la carpeta `sri-signer/`, y desde una terminal dentro de ella:

```bash
git init
git add .
git commit -m "Initial signer"
git branch -M main
git remote add origin https://github.com/TU_USUARIO/bm-sri-signer.git
git push -u origin main
```

### 2. Despliega en Railway

1. Entra a https://railway.com → **+ New Project** → **Deploy from GitHub repo**
2. Selecciona `bm-sri-signer`
3. Railway lo detecta como Node.js y empieza a instalar

### 3. Variables de entorno en Railway

En tu proyecto Railway → pestaña **Variables** → añade:

| Variable | Valor |
|---|---|
| `GMAIL_USER` | `casamusicalbuenamelodiajyg@gmail.com` |
| `GMAIL_APP_PASSWORD` | `qeybrxlvabmemrnn` (sin espacios) |
| `PORT` | `3000` |

> **NO** añadas el certificado aquí — viaja en cada request desde Lovable.

### 4. Generar URL pública

Railway → **Settings** → **Networking** → **Generate Domain**.
Copia la URL (ej: `bm-sri-signer-production.up.railway.app`).

### 5. Conectar con Lovable

Vuelve al chat de Lovable y dame esa URL. Yo te abro el formulario para guardarla como `SRI_SIGNER_URL`.

## Costo estimado

- Railway Hobby: **$5/mes** (incluye uso para este servicio)
- Gmail: gratis (límite 500 correos/día)

## Notas técnicas

- El firmado XAdES-BES usa una librería compatible con la ficha técnica del SRI Ecuador y certificados `.p12`.
- Las URLs SOAP del SRI cambian entre Pruebas (`celcer`) y Producción (`cel`) automáticamente según el `ambiente` que mandes.
- En Railway, abre la URL raíz del servicio y confirma que responda `version: "1.0.1-cert-diagnostics"`; si sigue en `1.0.0`, Railway no desplegó este código.
