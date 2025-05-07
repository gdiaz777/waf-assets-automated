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

## Scripts Overview

### upload-certificate-checkpoint-wafsaas.ts
This script is responsible for uploading certificates to Check Point WAF SaaS. It reads the `certificates.yaml` file to get the list of certificates and their associated domains, then uploads them to the WAF.

#### Key Features:
- Reads certificate details (PEM and key files) from `certificates.yaml`.
- Uploads certificates to Check Point WAF SaaS.
- Handles errors and logs the results.

#### Workflow:
1. Load the `certificates.yaml` file.
2. Authenticate with the WAF SaaS API.
3. Iterate through the list of certificates and upload them.
4. Log the results to a timestamped log file.

---

### deploy-assets-checkpoint-wafsaas.ts
This script automates the deployment of assets to Check Point WAF SaaS. It reads the `assets.yaml` file to get the list of assets and their configurations, then creates or updates the assets in the WAF.

#### Key Features:
- Reads asset configurations from `assets.yaml`.
- Creates or updates assets in Check Point WAF SaaS.
- Publishes and enforces changes.
- Handles errors and logs the results.

#### Workflow:
1. Load the `assets.yaml` file.
2. Authenticate with the WAF SaaS API.
3. Fetch the WAF profile ID.
4. Iterate through the list of assets:
   - Check if the asset already exists.
   - If it exists, skip it.
   - If it doesn't exist, create it.
5. Publish and enforce changes.
6. Log the results to a timestamped log file.

---

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

profile: The WAF profile name.
region: The region where the assets will be deployed.
assets: A list of assets to be deployed.
    name: The name of the asset.
    domain: A comma-separated list of domains for the asset.
    upstream: The upstream URL for the asset.
    owncertificate: Whether the asset uses its own certificate (true) or an AWS-managed certificate (false).
    cert_pem: Path to the PEM file for the certificate (required if owncertificate is true).
    cert_key: Path to the key file for the certificate (required if owncertificate is true).

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
profile: The WAF profile name.
region: The region where the assets will be deployed.
urls: A list of certificates to be uploaded.
url: The domain associated with the certificate.
cert_pem: Path to the PEM file for the certificate.
cert_key: Path to the key file for the certificate.
