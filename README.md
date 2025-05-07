# WAF SaaS Deployment and Certificate Upload Scripts

This repository contains two main scripts, `deploy-assets-checkpoint-wafsaas.ts` and `upload-certificate-checkpoint-wafsaas.ts`, designed to manage assets and certificates for WAF SaaS. Additionally, the repository includes configuration files (`.env`, `assets.yaml`, and `certificates.yaml`) that provide the necessary inputs for these scripts.

---

## **Dependencies**
```bash
	# install Deno - https://docs.deno.com/runtime/getting_started/installation/
	curl -fsSL https://deno.land/install.sh | sh

	# install dotenvx - https://dotenvx.com/
	curl -fsS https://dotenvx.sh | sudo sh

	# open terminal again with new environment
	exit

	# check versions
	deno --version
	dotenvx --version
```
--- 

## **Scripts Overview**

### **1. deploy-assets-checkpoint-wafsaas.ts**
This script is responsible for deploying assets to the WAF SaaS platform. It reads asset configurations from `assets.yaml` and performs the following tasks:
- Logs into the WAF SaaS platform using credentials from `.env`.
- Fetches the WAF profile and region from the configuration.
- Checks if the asset already exists:
  - If the asset exists, it skips the deployment.
  - If the asset does not exist, it creates a new asset using the provided configuration.
- Publishes and enforces changes after creating new assets.

#### **Key Functions**
- **`loadConfig(filename: string)`**: Loads and parses the YAML configuration file.
- **`wafLogin(url: string, clientId: string, accessKey: string)`**: Logs into the WAF SaaS platform and retrieves a session token.
- **`getAssets(matchSearch: string)`**: Fetches existing assets to check for duplicates.
- **`createAsset(assetData: any)`**: Creates a new asset based on the configuration.
- **`publishAndEnforce()`**: Publishes and enforces changes to apply the new asset configuration.

---

### **2. upload-certificate-checkpoint-wafsaas.ts**
This script handles the uploading of SSL/TLS certificates to the WAF SaaS platform. It reads certificate configurations from `certificates.yaml` and performs the following tasks:
- Logs into the WAF SaaS platform using credentials from `.env`.
- Fetches the WAF profile and region from the configuration.
- For each URL in the configuration:
  - Checks if the URL exists in the WAF profile.
  - Encrypts the private key using the WAF public key.
  - Uploads the certificate and updates the domain configuration.
  - Publishes and enforces changes after uploading the certificate.

#### **Key Functions**
- **`getEncryptionPublicKey(profileId: string, region: string)`**: Retrieves the public key for encrypting sensitive data.
- **`encryptPrivateKey(privateKey: string, publicKeyPem: string)`**: Encrypts the private key using AES and RSA encryption.
- **`addSensitiveField(profileId: string, region: string, encryptedFieldValue: string, encryptedKey: string, cert: string)`**: Adds the encrypted private key and certificate to the WAF profile.
- **`updateCertificate(uri: string, certificateARNForCloudfront: string, certificateARN: string, certId: string, certPem: string)`**: Updates the certificate for a specific domain.

---

## **Configuration Files**

### **1. .env**
This file contains the credentials and endpoint for logging into the WAF SaaS platform. It must be kept secure and should not be shared publicly.

#### **Structure**
``` yaml
WAFKEY=<your_client_id>
WAFSECRET=<your_access_key>
WAFAUTHURL=https://cloudinfra-gw.portal.checkpoint.com/auth/external
```

- **`WAFKEY`**: The client ID for authentication.
- **`WAFSECRET`**: The access key for authentication.
- **`WAFAUTHURL`**: The authentication endpoint for the WAF SaaS platform.

---

### **2. assets.yaml**
This file defines the assets to be deployed to the WAF SaaS platform.

#### **Structure**
``` yaml
configuration:
  profile: "<profile_name>"
  region: "<region>"

assets:
  - name: "<asset_name>"
    domain: "<domain>"
    owncertificate: <true|false>
    upstream: "<upstream_url>"
```

- **`profile`**: The WAF profile name.
- **`region`**: The region where the assets will be deployed.
- **`assets`**: A list of assets to be deployed.
  - **`name`**: The name of the asset.
  - **`domain`**: The domain associated with the asset. Comma separated and starting by https://
  - **`owncertificate`**: Indicates whether the asset uses its own certificate (`true`) or an AWS-managed certificate (`false`).
  - **`upstream`**: The upstream URL for the asset.

---

### **3. certificates.yaml**
This file defines the certificates to be uploaded to the WAF SaaS platform.

#### **Structure**
``` yaml
configuration:
  profile: "<profile_name>"
  region: "<region>"

urls:
  - url: "<https_url>"
    domain: "<domain>"
    cert_pem: "<path_to_certificate_file>"
    cert_key: "<path_to_private_key_file>"
```

- **`profile`**: The WAF profile name.
- **`region`**: The region where the certificates will be uploaded.
- **`urls`**: A list of URLs and their associated certificates.
  - **`url`**: The HTTPS URL for the domain.
  - **`domain`**: The domain name.
  - **`cert_pem`**: The path to the certificate file.
  - **`cert_key`**: The path to the private key file.

---

## **Usage Instructions**

1. **Set Up Configuration Files**
   - Fill in the `.env` file with your WAF SaaS credentials.
   - Define your assets in `assets.yaml`.
   - Define your certificates in `certificates.yaml`.

2. **Run the Scripts**
   - To deploy assets, run:
     ```bash
     dotenvx run -- deno run -A deploy-assets-checkpoint-wafsaas.ts 
     ```
   - To upload certificates, run:
     ```bash
     dotenvx run -- deno run -A upload-certificate-checkpoint-wafsaas.ts
     ```

3. **Check Logs**
   - Logs for each script will be generated in the current directory with timestamps.

---

## **Security Notes**
- Ensure [.env](http://_vscodecontentref_/0) is not shared or committed to version control.
- Use secure file permissions for [.env](http://_vscodecontentref_/1), [assets.yaml](http://_vscodecontentref_/2), and [certificates.yaml](http://_vscodecontentref_/3).
- Rotate your WAF credentials periodically.

--- 


