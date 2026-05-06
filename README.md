# WAF SaaS Deployment and Certificate Upload Scripts

This repository contains two Deno/TypeScript scripts to automate the management of assets (web applications) and certificates in **Check Point CloudGuard WAF SaaS / Infinity Next**:

- `deploy-assets-checkpoint-waf-saas.ts` — creates assets from `assets.yaml`.
- `upload-certificate-checkpoint-wafsaas.ts` — uploads BYOC (Bring Your Own Cert) certificates from `certificates.yaml`.

Both speak the GraphQL API of the Infinity Portal (`/app/waf/graphql`) and consume credentials from the `.env` file.

> **Note about the API**: this code follows the current API shape verified against the portal. The old mutations `addSensitiveField`, `updateDomainCertificate` and `publishChanges` have been replaced by `createSaasCertificate`, `linkSaasCertificate` and `asyncPublishChanges` respectively. The public Postman collection in `CheckPointSW/infinitynext-mgmt-api-resources` may be out of date.

---

## Dependencies

```bash
# Install Deno - https://docs.deno.com/runtime/getting_started/installation/
curl -fsSL https://deno.land/install.sh | sh

# Install dotenvx - https://dotenvx.com/
curl -fsS https://dotenvx.sh | sudo sh

# Reopen the terminal so the new PATH is picked up
exit

# Verify versions
deno --version
dotenvx --version
```

---

## Scripts overview

### 1. `deploy-assets-checkpoint-waf-saas.ts`

Deploys assets to the configured AppSecSaaS profile. For each asset in the YAML:

1. Checks whether it already exists (`getWafAssets` with the `class: ["workload"]` filter). If it exists, the asset is skipped.
2. Pre-flights `validateName` to verify the name does not collide with another object.
3. Creates the asset with `newAssetByWizard`, choosing between an own certificate (BYOC) or a WAF-managed certificate based on the `owncertificate` flag in the YAML.
4. **At the end of the loop**, runs `asyncPublishChanges` + `enforcePolicy` ONCE to publish all the new assets in a single batch (large-load optimization).

#### Key functions

- `loadConfig(filename)` — loads and parses a YAML file.
- `wafLogin(url, clientId, accessKey)` — authenticates against the Infinity Portal and returns the JWT.
- `wafProfiles()` — resolves the profile UUID from its name.
- `getWafAssets(matchSearch)` — lists existing assets (replaces the old `getAssets`).
- `validateName(name)` — name uniqueness pre-flight.
- `newAssetByWizard(...)` — single creation function, parameterised with `ownCertificate: boolean`. Internally sends `saasCertificateType: "BYOC"` or `"CPManaged"`.
- `setHostHeader(assetId, host)` — applies the optional Host header rewrite via `updateWebApplicationProxySetting` (only invoked when `host` is provided in the YAML).
- `asyncPublishChanges()`, `enforcePolicy()`, `waitForTask(id)`, `publishAndEnforce()` — publish flow.
- `discardChanges()` — rollback if publish fails.

### 2. `upload-certificate-checkpoint-wafsaas.ts`

Uploads BYOC certificates and links them to existing asset domains. For each URL in the YAML:

1. Asks the backend for the RSA public key (`getPublicKey`, `sensitiveFieldName: "nexusCertificate"`).
2. Encrypts the private key with a hybrid scheme **AES-CBC + RSA-OAEP** (the private key NEVER travels in clear).
3. Creates the certificate as a first-class object with `createSaasCertificate` → receives a `certificateId`.
4. Links the certificate to the domain with `linkSaasCertificate(domain, certificateId)`.
5. **At the end**, runs `asyncPublishChanges` + `enforcePolicy` ONCE.

#### Key functions

- `getEncryptionPublicKey(profileId, region)` — fetches the backend public key used for encryption.
- `encryptPrivateKey(privateKey, publicKeyPem)` — hybrid AES + RSA encryption.
- `createSaasCertificate(...)` — creates the certificate object (replaces the old `addSensitiveField`).
- `linkSaasCertificate(domain, certificateId)` — links cert ↔ domain (replaces the old `updateDomainCertificate`).

---

## Configuration files

### 1. `.env`

Credentials and endpoint of the Infinity Portal. **Never commit to git.**

```
WAFKEY=<your_client_id>
WAFSECRET=<your_access_key>
WAFAUTHURL=https://cloudinfra-gw.portal.checkpoint.com/auth/external
```

Credentials are generated in *Infinity Portal → Global Settings → API Keys*, with service "Web Application & API Protection".

### 2. `assets.yaml`

Defines the assets that `deploy-assets-...` will create.

```yaml
configuration:
  profile: "<profile_name>"
  region: "<region>"

assets:
  - name: "<asset_name>"
    domain: "<https_url1, https_url2, ...>"
    owncertificate: <true|false>
    upstream: "<upstream_url>"
    host: "<optional_host_header>"
```

- `profile` — name of the AppSecSaaS profile (not the UUID; the script resolves it).
- `region` — e.g. `eu-west-1`.
- `name` — unique asset name.
- `domain` — one or more URLs separated by comma, each `https://...`.
- `owncertificate`:
  - `true` → BYOC mode (Bring Your Own Cert). The certificate must be uploaded later with the other script. Sent as `saasCertificateType: "BYOC"`.
  - `false` → Check Point–managed certificate (auto-provisioned). Sent as `saasCertificateType: "CPManaged"`.
- `upstream` — backend URL the WAF forwards traffic to.
- `host` *(optional)* — Host header value sent to the upstream. Useful when the upstream LB does virtual-host routing on a different hostname than the public domain (e.g. AWS ELB routing on the internal hostname). When set, the script applies it via `updateWebApplicationProxySetting` after the asset is created.

### 3. `certificates.yaml`

Defines the certificates that `upload-certificate-...` will upload.

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

- `cert_pem` — PEM file with the full chain (leaf cert + intermediates).
- `cert_key` — PEM private key, **without passphrase**.

---

## Recommended execution order

1. Create assets with own certificate (BYOC):
   ```bash
   dotenvx run -- deno run -A deploy-assets-checkpoint-waf-saas.ts
   ```
2. Upload certificates to the freshly created domains:
   ```bash
   dotenvx run -- deno run -A upload-certificate-checkpoint-wafsaas.ts
   ```

If every asset is `owncertificate: false` (managed by the WAF), only step 1 is needed.

Each run produces a timestamped log in the current directory:

- `YYYY-MM-DD-HH-MM_deploy-assets_output.log`
- `YYYY-MM-DD-HH-MM_upload-certificates_output.log`

---

## Large-load optimization

Both scripts run `publishAndEnforce` **only once at the end of the loop**, not per element. This drastically reduces total runtime when processing tens or hundreds of assets/certificates, because the `publish + enforce + waitForTask` flow can take from 30 seconds to several minutes per iteration. The scripts also:

- Skip assets that already exist (`getWafAssets` + filter by name).
- Pre-flight with `validateName` before creating.
- Accumulate non-fatal errors (a failing cert → log and move on) without aborting the whole batch.

---

## Security

- **Private key encryption**: certificates are uploaded with a hybrid AES-CBC + RSA-OAEP encryption. The private key is encrypted with AES-256, and the AES key is encrypted with the RSA public key the backend hands out via `getPublicKey`. Only Check Point can decrypt the bundle. The public part of the certificate (PEM) travels in clear because it is not a secret.
- **Do not commit** `.env`, `assets.yaml`, `certificates.yaml`, or any `.pem` files containing sensitive material.
- Restrictive permissions locally: `chmod 600 .env *.pem`.
- Rotate the Infinity Portal API keys periodically.

---

## Notes about the GraphQL operations

| Operation                  | Old                            | Current                       |
|----------------------------|--------------------------------|-------------------------------|
| List assets                | `getAssets` (`AssetsName`)     | `getWafAssets` (`WafAssetsName`, filter `class:["workload"]`) |
| Upload cert (encrypted)    | `addSensitiveField`            | `createSaasCertificate` (BYOC) |
| Link cert → domain         | `updateDomainCertificate`      | `linkSaasCertificate(domain, certificateId)` |
| Publish changes            | `publishChanges` (sync)        | `asyncPublishChanges`         |
| Enforce policy             | `enforcePolicy`                | `enforcePolicy` (unchanged)   |
| AES + RSA-OAEP encryption  | same                           | same                          |
| Name pre-flight            | —                              | `validateName(name, "Asset")` |
| Host header rewrite        | n/a                            | `updateWebApplicationProxySetting` (`isSetHeader` + `setHeader=Host:<value>`) |
