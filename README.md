# Declarative creation or WAFaaS assets

This scenario was validated in Github Codespace. Consider opening repo in Codespace and running the instructions there (or in local devcontainer).


### ⚠️ Important Notes

> **NOTE:** This is a PoC/concept and not production-ready code. It has not been tested for all edge cases and should be used with caution.

> **<span style="color:red;">SELF-SIGNED CERTIFICATES ARE NOT WORKING WITH WAFaaS.</span>** Documentation will be updated soon to reflect this limitation.

### Dependencies

```shell
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

### WAF API key

Login to your CloudGuard WAF tenant and setup new admin keys for CloudGuard WAF:
https://portal.checkpoint.com/dashboard/settings/api-keys

![alt text](img/api-keys.png)

Create new `.env` file in the root of the project and add the following variables:

```env
# .env
# WAF API key
WAFKEY=xxx
# WAF API secret
WAFSECRET=yyy
# AUTH URL
WAFAUTHURL=https://cloudinfra-gw.portal.checkpoint.com/auth/external
```

You may validate your API key using the following command:

```shell
# validate WAF API key
dotenvx run -- env | grep ^WAF
```

### Create or review WAFaaS Profile

Visit WAFaaS asset in UI and note asset name and region.

https://portal.checkpoint.com/dashboard/appsec/cloudguardwaf#/waf-policy/profiles/ 

For example, the profile type is `CloudGuard WAF SaaS Profile` name is `saas-stockholm` and the region for Stockholm is `eu-north-1`.

| **Location** | **AWS Region Name** |
|--------------|---------------------|
| Stockholm    | eu-north-1          |
| Milan        | eu-south-1          |
| Ireland      |               |

![alt text](./img/wafaas-profile.png)


### Review assets.yaml definiton

`assets.yaml` file contains the WAFaaS asset definition. Here is typical template based on inputs we know:

```yaml
config:
  profile: "saas-stockholm"
  region: "eu-north-1"

assets:
  - name: "example.com" # asset name
    domain: "https://example1.com,https://example2.com,https://example3.com" # each url from the asset comma separated
    owncertificate: false # could be true or false if false, you have to provide the path of the certificate (full chain) and the key in pem format
    upstream: "https://example.org"
    cert_pem: "server.crt" # certificate file location
    cert_key: "server.key" # key file location

  - name: "ifconfig.example.com" # asset name
    domain: "https://ifconfig.example.com" # each url from the asset comma separated
    owncertificate: true # if true, the certificate is an AWS hosted certificate
    upstream: "https://ifconfig.me"
```

### Execute asset provisioning

Script checks if asserts already exist and if not, creates them. It also uploads custom certificates as provided in files. 

```shell
# check assets to create
cat assets.yaml

# execute deployment
dotenvx run -- deno run -A deploy-waf-with-own-cert.ts
```

### Expected results

Assets are created per YAML declaration in `assets.yaml` file.
Uploaded certificates are used for the assets and can be confirmed in the UI under the profile.

![alt text](img/domain-cert-uploaded.png)

Execution

```shell
# execute deployment - all is done, so we check only state of Deployment
dotenvx run -- deno run -A deploy-waf-with-own-cert.ts
```

### Troubleshooting

- so far this is PoC/concept and if you want to run again for same list of assets, you might want to delete them first, publish&enforce and start again
