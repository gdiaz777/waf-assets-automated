# Check Point WAF SaaS Automation Scripts

This repository contains two main scripts, `upload-certificate-checkpoint-wafsaas.ts` and `deploy-assets-checkpoint-wafsaas.ts`, along with configuration files `assets.yaml` and `certificates.yaml`. These scripts automate the deployment of assets and the management of certificates for Check Point WAF SaaS.

---

## Table of Contents
1. [Scripts Overview](#scripts-overview)
    - [upload-certificate-checkpoint-wafsaas.ts](#upload-certificate-checkpoint-wafsaasts)
    - [deploy-assets-checkpoint-wafsaas.ts](#deploy-assets-checkpoint-wafsaasts)
2. [Configuration Files](#configuration-files)
    - [assets.yaml](#assetsyaml)
    - [certificates.yaml](#certificatesyaml)
3. [How to Use](#how-to-use)
4. [Prerequisites](#prerequisites)
5. [Logging](#logging)

---

# Scripts Overview

## Purpose

The purpose of `deploy-assets-checkpoint-wafsaas.ts` is to:
- Automate the deployment of assets to the WAF SaaS platform.
- Ensure assets are configured with the correct upstream URLs and certificates.
- Publish and enforce changes after deployment.

---

## Key Features

1. **Asset Deployment**:
   - Automatically creates assets based on the configuration provided in `assets.yaml`.
   - Skips assets that already exist to avoid duplication.

2. **Certificate Management**:
   - Supports assets with custom certificates (`owncertificate: true`).
   - Integrates with AWS for automatic certificate creation if needed.

3. **Change Management**:
   - Publishes and enforces changes after asset creation to ensure the configuration is applied.

4. **Logging**:
   - Generates detailed logs for each operation, including success and failure messages.

---

## How It Works

1. **Configuration Loading**:
   - The script reads the asset configuration from `assets.yaml`, which defines the assets to be deployed.

2. **WAF SaaS Login**:
   - Logs in to the WAF SaaS platform using credentials provided in environment variables.

3. **Profile and Region Setup**:
   - Fetches the WAF profile and region specified in the configuration.

4. **Asset Deployment**:
   - Iterates through the assets defined in `assets.yaml`.
   - Checks if the asset already exists:
     - If it exists, skips deployment.
     - If it does not exist, creates the asset with the specified configuration.

5. **Change Publishing and Enforcement**:
   - Publishes and enforces changes after deploying assets to ensure the configuration is applied.

6. **Logging**:
   - Logs the results of each operation to a timestamped log file.

---

## How to Run the Script

``` yaml
dotenvx run -- deno run -A deploy-assets-checkpoint-wafsaas.ts
```
---
## Logs
The script generates a log file in the current directory with the format <timestamp>_deploy-assets_output.log. This log file contains detailed information about the operations performed, including success and failure messages.

## Notes
- Ensure the assets.yaml file is correctly formatted to avoid parsing errors.
- Use the log file to debug any issues during deployment.
- If an asset fails to deploy, the script will log the error and continue with the next asset.
## Configuration Files

### assets.yaml
This file contains the configuration for assets to be deployed to Check Point WAF SaaS.

#### Example Structure:
```yaml
configuration:
  profile: "example-profile"
  region: "eu-west-1"

assets:
  - name: "example-asset"
    domain: "https://example.com, https://example2.com"
    upstream: "https://upstream.example.com"
    owncertificate: true
    cert_pem: "/path/to/cert.pem"
    cert_key: "/path/to/key.pem"
  - name: "another-asset"
    domain: "https://another.com"
    upstream: "https://upstream.another.com"
    owncertificate: false

```
### Fields:

- profile: The WAF profile name.
- region: The region where the assets will be deployed.
- assets: A list of assets to be deployed.
    - name: The name of the asset.
    - domain: A comma-separated list of domains for the asset.
    - upstream: The upstream URL for the asset.
    - owncertificate: Whether the asset uses its own certificate (true) or an AWS-managed certificate (false).
    - cert_pem: Path to the PEM file for the certificate (required if owncertificate is true).
    - cert_key: Path to the key file for the certificate (required if owncertificate is true).

### certificates.yaml
This file contains the configuration for certificates to be uploaded to Check Point WAF SaaS.

#### Example Structure:
```yaml
    configuration:
      profile: "WAF SaaS Test2"
      region: "eu-west-1"
    urls:
      - url: "https://example.com"
        cert_pem: "/path/to/example_cert.pem"
        cert_key: "/path/to/example_key.pem"
      - url: "https://example2.com"
        cert_pem: "/path/to/example2_cert.pem"
        cert_key: "/path/to/example2_key.pem"
```
### Fields:

- profile: The WAF profile name.
- region: The region where the assets will be deployed.
- urls: A list of certificates to be uploaded.
    - url: The domain associated with the certificate.
    - cert_pem: Path to the PEM file for the certificate.
    - cert_key: Path to the key file for the certificate.


