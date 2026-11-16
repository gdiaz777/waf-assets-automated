# waf-assets-automated/ — Claude context

Tooling that creates **Web Application assets** and uploads **BYOC certificates** in Check Point CloudGuard WAF SaaS / Infinity Next, plus a standalone publish+enforce helper.

For the workspace-wide context (stack, shared API patterns, hybrid cert encryption, etc.) see [../CLAUDE.md](../CLAUDE.md). User-facing docs are in [README.md](README.md).

---

## What is here

| File | Purpose |
|------|---------|
| `deploy-assets-checkpoint-waf-saas.ts` | Creates each asset in `assets.yaml`. Picks BYOC or CPManaged from the `owncertificate` flag. Pre-flights `validateName`. Single publish+enforce at end of batch. |
| `upload-certificate-checkpoint-wafsaas.ts` | Uploads BYOC certs from `certificates.yaml`. Hybrid AES-CBC + RSA-OAEP encryption of the private key. `createSaasCertificate` → `linkSaasCertificate`. Single publish+enforce at end. |
| `enforce-checkpoint-wafsaas.ts` | Standalone helper — `asyncPublishChanges` + `enforcePolicy` + `waitForTask`. Use when the portal shows *"Certificate issued. Enforce policy to proceed."* or to apply any leftover pending session. |
| `assets.yaml` | Asset definitions. See below. |
| `certificates.yaml` | Certificate definitions. See below. |
| `.env` | Secrets (`WAFAUTHURL` / `WAFKEY` / `WAFSECRET`). Gitignored. |
| `*.pem`, `*.key`, `*.crt`, `*.cer`, `*.pfx` | Certificate material. Gitignored. |
| `*_deploy-assets_output.log`, `*_upload-certificates_output.log` | Per-run append-only logs. Gitignored. |

---

## Recommended execution order

```bash
# 1. Create assets (BYOC ones will have no cert yet)
dotenvx run -- deno run -A deploy-assets-checkpoint-waf-saas.ts

# 2. Upload certificates for the BYOC domains created in step 1
dotenvx run -- deno run -A upload-certificate-checkpoint-wafsaas.ts

# 3. Only if the portal still shows pending changes — usually not needed,
#    because steps 1 and 2 already publish+enforce at the end
dotenvx run -- deno run -A enforce-checkpoint-wafsaas.ts
```

If every asset is `owncertificate: false` (CPManaged), step 1 alone is sufficient.

---

## `assets.yaml` schema

```yaml
configuration:
  profile: "<profile_name>"        # AppSecSaaS profile name (script resolves UUID)
  region: "<region>"               # e.g. eu-west-1

assets:
  - name: "<asset_name>"           # unique asset name
    domain: "<url1, url2, ...>"    # comma-separated https://… URLs
    owncertificate: <true|false>   # true → BYOC, false → CPManaged
    upstream: "<upstream_url>"     # backend the WAF forwards to
    host: "<optional_host_value>"  # optional Host header rewrite (added via
                                   # updateWebApplicationProxySetting)
```

When `host` is set, the script applies it after creation by sending two proxy items: `isSetHeader=true` and `setHeader=Host:<value>`. A failure on Host header does NOT undo the asset creation — both outcomes are logged separately.

---

## `certificates.yaml` schema

```yaml
configuration:
  profile: "<profile_name>"
  region: "<region>"

urls:
  - url: "<https_url>"             # informational, used for the log line
    domain: "<domain>"             # the domain the cert is linked to
    cert_pem: "<fullchain_pem>"    # path to the leaf + intermediates PEM
    cert_key: "<privkey_pem>"      # path to the private key (NO passphrase)
```

The private key MUST be unencrypted before the script reads it; the certificate MUST be the full chain. A wildcard / SAN cert created once can be linked to multiple domains by reusing the same `cert_pem` / `cert_key` across entries — `createSaasCertificate` mints a new object each time and the link is per-domain.

---

## Script-specific notes

### `deploy-assets-checkpoint-waf-saas.ts`

- **Skips existing assets** by name (case-sensitive exact match via `getWafAssets` + filter).
- **Pre-flights `validateName(name, "Asset")`** — fails fast if another object type already reserved the name.
- **`newAssetByWizard` quirks**: the wizard body mirrors what the portal posts. Defaults applied:
  - `stage: "Staging"`, `state: "Active"`.
  - Source identification via `XForwardedFor` (override if the asset sits behind a different proxy).
  - Default practices: WebApplication (Learn + WebAttacks AccordingToPractice + IPS AccordingToPractice), APIProtection (all Disabled), AIGuard (Disabled).
- **Host header rewrite** is invoked **after** asset creation via `updateWebApplicationProxySetting` — only when the YAML provides `host`.
- **Single publish/enforce** at the end. Run unconditionally so any pending session from a prior failed run also lands.
- **Rollback**: if `publishAndEnforce` fails, `discardChanges` is called and the failure is logged.

### `upload-certificate-checkpoint-wafsaas.ts`

- **Hybrid AES-CBC + RSA-OAEP** encryption — see [`encryptPrivateKey`](upload-certificate-checkpoint-wafsaas.ts). IV is concatenated at the **start** of the ciphertext (backend convention), not sent as a separate field.
- **`sensitiveFieldName: "nexusCertificate"`** is what binds the public key from `getPublicKey` to the right backend secret type. Do not change unless uploading a different secret kind.
- **`createSaasCertificate`** mints a first-class cert object; the cert file name uses the portal format `fullchain.pem_DD-Mon-YYYY_HH:MM:SS` for display.
- **`linkSaasCertificate(domain, certificateId)`** is the second step — one cert can be linked to many domains by issuing this call multiple times with the same `certificateId`.
- A failure in one cert does NOT abort the batch — the loop logs and moves on. The publish/enforce at the end captures everything that did succeed.

### `enforce-checkpoint-wafsaas.ts`

- The smallest tool — just login + `asyncPublishChanges` + `waitForPublishedSession` (best-effort, never gates) + `enforcePolicy` + `waitForTask`. Run when the portal shows pending changes that no script applied.

---

## Common pitfalls in this folder

- **YAML parsing**: the scripts use `jsr:@std/yaml`. A stray tab or wrong indentation aborts before the API is touched. The `console.log("config:", …)` at the start of each script is the easiest checkpoint.
- **Profile name vs UUID**: configure the profile by name in YAML; the script resolves the UUID via `ProfilesName`. If the lookup fails, check that the API key tenant matches the profile's tenant.
- **Cert / key file paths in YAML** are resolved relative to the cwd at run time, not the script directory. Always `cd` into `waf-assets-automated/` (or pass absolute paths) before running.
- **Mixing BYOC + CPManaged in the same batch** is fine. The BYOC ones remain "Certificate pending" until `upload-certificate-…` runs.
