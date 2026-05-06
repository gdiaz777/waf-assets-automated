# WAF SaaS Deployment and Certificate Upload Scripts

Este repositorio contiene dos scripts en Deno/TypeScript para automatizar la gestión de assets (aplicaciones web) y certificados en **Check Point CloudGuard WAF SaaS / Infinity Next**:

- `deploy-assets-checkpoint-waf-saas.ts` — crea assets a partir de `assets.yaml`.
- `upload-certificate-checkpoint-wafsaas.ts` — sube certificados propios (BYOC) a partir de `certificates.yaml`.

Ambos hablan con la API GraphQL del Infinity Portal (`/app/waf/graphql`) y usan las credenciales del fichero `.env`.

> **Nota sobre la API**: este código sigue el shape actual de la API verificado contra el portal. Las antiguas mutaciones `addSensitiveField`, `updateDomainCertificate` y `publishChanges` han sido reemplazadas por `createSaasCertificate`, `linkSaasCertificate` y `asyncPublishChanges` respectivamente. La colección Postman pública del repositorio `CheckPointSW/infinitynext-mgmt-api-resources` puede estar desactualizada.

---

## Dependencias

```bash
# Instalar Deno - https://docs.deno.com/runtime/getting_started/installation/
curl -fsSL https://deno.land/install.sh | sh

# Instalar dotenvx - https://dotenvx.com/
curl -fsS https://dotenvx.sh | sudo sh

# Reabrir terminal para refrescar el PATH
exit

# Verificar versiones
deno --version
dotenvx --version
```

---

## Resumen de los scripts

### 1. `deploy-assets-checkpoint-waf-saas.ts`

Despliega assets en el profile AppSecSaaS configurado. Para cada asset del YAML:

1. Comprueba si ya existe (`getWafAssets` con filtro `class: ["workload"]`). Si existe, lo salta.
2. Pre-flight `validateName` para verificar que el nombre no choca con otros objetos.
3. Crea el asset con `newAssetByWizard`, eligiendo entre cert propio (BYOC) o cert gestionado por el WAF según el flag `owncertificate` del YAML.
4. **Al final del bucle**, ejecuta UNA sola vez `asyncPublishChanges` + `enforcePolicy` para publicar todos los assets nuevos en lote (optimización para grandes cargas).

#### Funciones clave

- `loadConfig(filename)` — carga y parsea un YAML.
- `wafLogin(url, clientId, accessKey)` — autentica contra el Infinity Portal, devuelve el JWT.
- `wafProfiles()` — resuelve el UUID del profile a partir de su nombre.
- `getWafAssets(matchSearch)` — lista assets existentes (sustituye al antiguo `getAssets`).
- `validateName(name)` — pre-flight de unicidad de nombre.
- `newAssetByWizard(...)` — única función de creación, parametrizada por `ownCertificate: boolean`. Internamente envía `saasCertificateType: "BYOC"` o `"WAF_MANAGED"`.
- `asyncPublishChanges()`, `enforcePolicy()`, `waitForTask(id)`, `publishAndEnforce()` — flujo de publicación.
- `discardChanges()` — rollback si publish falla.

### 2. `upload-certificate-checkpoint-wafsaas.ts`

Sube certificados propios (BYOC) y los enlaza a dominios de assets existentes. Para cada URL del YAML:

1. Pide la public key RSA al backend (`getPublicKey`, `sensitiveFieldName: "nexusCertificate"`).
2. Cifra la private key con un esquema híbrido **AES-CBC + RSA-OAEP** (la private key NUNCA viaja en claro).
3. Crea el certificado como objeto de primer nivel con `createSaasCertificate` → recibe `certificateId`.
4. Enlaza el certificado al dominio con `linkSaasCertificate(domain, certificateId)`.
5. **Al final**, ejecuta UNA sola vez `asyncPublishChanges` + `enforcePolicy`.

#### Funciones clave

- `getEncryptionPublicKey(profileId, region)` — obtiene la public key del backend para cifrar.
- `encryptPrivateKey(privateKey, publicKeyPem)` — cifrado híbrido AES + RSA.
- `createSaasCertificate(...)` — crea el objeto certificado (sustituye al antiguo `addSensitiveField`).
- `linkSaasCertificate(domain, certificateId)` — enlaza cert ↔ dominio (sustituye al antiguo `updateDomainCertificate`).

---

## Ficheros de configuración

### 1. `.env`

Credenciales y endpoint del Infinity Portal. **No subir nunca a git.**

```
WAFKEY=<your_client_id>
WAFSECRET=<your_access_key>
WAFAUTHURL=https://cloudinfra-gw.portal.checkpoint.com/auth/external
```

Las credenciales se generan en *Infinity Portal → Global Settings → API Keys*, con servicio "Web Application & API Protection".

### 2. `assets.yaml`

Define los assets que `deploy-assets-...` va a crear.

```yaml
configuration:
  profile: "<profile_name>"
  region: "<region>"

assets:
  - name: "<asset_name>"
    domain: "<https_url1, https_url2, ...>"
    owncertificate: <true|false>
    upstream: "<upstream_url>"
```

- `profile` — nombre del profile AppSecSaaS (no el UUID; el script lo resuelve).
- `region` — ej. `eu-west-1`.
- `name` — nombre único del asset.
- `domain` — una o varias URLs separadas por coma, cada una `https://...`.
- `owncertificate`:
  - `true` → modo BYOC (Bring Your Own Cert). Hay que subir el cert luego con el otro script.
  - `false` → cert gestionado por el WAF (auto-provisionado por Check Point).
- `upstream` — URL del backend al que el WAF reenvía el tráfico.

> **Sobre `WAF_MANAGED`**: el valor del enum para cert gestionado se ha asumido como `"WAF_MANAGED"` por convención. Si la API lo rechaza, ajustar la constante `SAAS_CERT_TYPE_WAF_MANAGED` al inicio del script (candidatos alternativos: `"AWS_MANAGED"`, `"AUTO"`, `"MANAGED"`).

### 3. `certificates.yaml`

Define los certificados que `upload-certificate-...` va a subir.

```yaml
configuration:
  profile: "<profile_name>"
  region: "<region>"

urls:
  - url: "<https_url>"
    domain: "<domain>"
    cert_pem: "<path_to_fullchain_pem>"
    cert_key: "<path_to_privkey_pem>"
```

- `cert_pem` — fichero PEM con la cadena completa (cert hoja + intermedios).
- `cert_key` — private key PEM, **sin passphrase**.

---

## Orden recomendado de ejecución

1. Crear los assets con cert propio (BYOC):
   ```bash
   dotenvx run -- deno run -A deploy-assets-checkpoint-waf-saas.ts
   ```
2. Subir los certificados a los dominios recién creados:
   ```bash
   dotenvx run -- deno run -A upload-certificate-checkpoint-wafsaas.ts
   ```

Si todos los assets son `owncertificate: false` (gestionado por el WAF), basta con el primer paso.

Cada ejecución genera un log con timestamp en el directorio actual:

- `YYYY-MM-DD-HH-MM_deploy-assets_output.log`
- `YYYY-MM-DD-HH-MM_upload-certificates_output.log`

---

## Optimización para grandes cargas

Ambos scripts ejecutan `publishAndEnforce` **una sola vez al final del bucle**, no por cada elemento. Esto reduce drásticamente el tiempo total cuando se procesan decenas o cientos de assets/certificados, porque el flujo `publish + enforce + waitForTask` cuesta entre 30s y varios minutos por iteración. Los scripts también:

- Saltan los assets que ya existen (`getWafAssets` + filtro por nombre).
- Hacen pre-flight con `validateName` antes de crear.
- Acumulan errores no fatales (cert que falla → log y siguiente) sin abortar todo el batch.

---

## Seguridad

- **Cifrado de la private key**: el certificado se sube con cifrado híbrido AES-CBC + RSA-OAEP. La private key se cifra con AES-256 y la AES key se cifra con la public key RSA del backend, generada por petición vía `getPublicKey`. Solo Check Point puede descifrar el bundle. La parte pública del certificado (PEM) viaja en claro porque no es secreta.
- **No commitear** `.env`, `assets.yaml`, `certificates.yaml` ni los ficheros `.pem` con material sensible.
- Permisos restrictivos en local: `chmod 600 .env *.pem`.
- Rotar periódicamente las API keys del Infinity Portal.

---

## Notas sobre las llamadas GraphQL

| Operación               | Antigua                        | Actual                       |
|-------------------------|--------------------------------|------------------------------|
| Listar assets           | `getAssets` (`AssetsName`)     | `getWafAssets` (`WafAssetsName`, filtro `class:["workload"]`) |
| Subir cert (encrypted)  | `addSensitiveField`            | `createSaasCertificate` (BYOC)  |
| Enlazar cert → dominio  | `updateDomainCertificate`      | `linkSaasCertificate(domain, certificateId)` |
| Publicar cambios        | `publishChanges` (síncrono)    | `asyncPublishChanges`        |
| Aplicar política        | `enforcePolicy`                | `enforcePolicy` (sin cambios) |
| Cifrado AES + RSA-OAEP  | igual                          | igual                        |
| Pre-flight nombre       | —                              | `validateName(name, "Asset")` |
