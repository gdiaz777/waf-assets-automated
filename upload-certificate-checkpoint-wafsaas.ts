// ============================================================================
// upload-certificate-checkpoint-wafsaas.ts
// ----------------------------------------------------------------------------
// Uploads BYOC SSL/TLS certificates to Check Point CloudGuard WAF SaaS /
// Infinity Next and links them to the domains of assets that already exist
// in the profile.
//
// Security model: the private key NEVER travels in clear. It is encrypted
// locally with AES-CBC; the AES key is encrypted with the RSA-OAEP public
// key the backend hands out (hybrid encryption). Only Check Point can
// decrypt with their RSA private key, and only then can they recover the
// AES key to open the blob.
//
// Optimization: publishAndEnforce is called ONLY ONCE at the end, and only
// if at least one certificate was uploaded successfully.
// ============================================================================

import { encode as encodeBase64 } from "https://deno.land/std@0.208.0/encoding/base64.ts";
import { parse as parseYaml } from "jsr:@std/yaml";

// Infinity Portal WAF GraphQL endpoint (the double slash is intentional).
const WAF_GRAPHQL_URL = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql";

// Global process state. Filled in inside main() and reused across functions.
let wafSession: any = null;     // Login response (contains the JWT in data.token).
let PROFILE: string | null = null;       // Target AppSecSaaS profile name.
let REGION: string | null = null;        // Profile region.
let PROFILE_PID: string | null = null;   // Profile UUID.
let FILEPATH: string | null = null;      // Output log path with timestamp.

// Loads and parses a YAML file.
async function loadConfig(filename: string) {
    const configText = await Deno.readTextFile(filename);
    try {
        const config = parseYaml(configText);
        return config;
    } catch (error) {
        console.error("Error parsing YAML:", error);
        return null;
    }
}

// Logs in to the Infinity Portal. Returns the object holding the JWT.
async function wafLogin(url: string, clientId: string, accessKey: string) {
    try {
        const response = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ clientId, accessKey }),
        });

        if (response.ok) {
            console.log("Login successful");
            return await response.json();
        }
        console.error("Login failed with status:", response.status);
        console.error("Error details:", await response.json());
    } catch (error) {
        console.error("Error during WAF login:", error);
    }
    return null;
}

// Resolves the profile UUID from its name (PROFILE).
async function wafProfiles() {
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        operationName: "ProfilesName",
        variables: {},
        query: "query ProfilesName($matchSearch: String, $filters: ProfileFilter, $paging: Paging, $sortBy: SortBy) {\n  getProfiles(\n    matchSearch: $matchSearch\n    filters: $filters\n    paging: $paging\n    sortBy: $sortBy\n  ) {\n    id\n    name\n    __typename\n  }\n}\n",
    };
    try {
        const response = await fetch(WAF_GRAPHQL_URL, {
            method: "POST",
            headers,
            body: JSON.stringify(body),
        });
        if (response.ok) {
            const data = await response.json();
            const profiles = data?.data?.getProfiles?.map((p: any) => ({ id: p.id, name: p.name })) ?? [];
            console.log("Profiles fetched successfully:", profiles);
            const match = profiles.find((p: any) => p.name === PROFILE);
            if (match) {
                console.log(`Matching profile found: ${match.name} with ID ${match.id}`);
                return match.id;
            }
            console.error(`No profile found with the name "${PROFILE}"`);
        } else {
            console.error("Failed to fetch profiles. Status:", response.status);
            console.error("Error details:", await response.json());
        }
    } catch (error) {
        console.error("Error during fetching profiles:", error);
    }
    return null;
}

// Publishes pending tenant changes (asynchronous). Replaces the old
// publishChanges. Validation runs in the background; propagation to the
// data plane is triggered separately by enforcePolicy.
async function asyncPublishChanges() {
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        operationName: "asyncPublishChanges",
        variables: {
            profileTypes: ["Docker", "CloudGuardAppSecGateway", "Embedded", "Kubernetes", "AppSecSaaS"],
        },
        query: "mutation asyncPublishChanges($profileTypes: [ProfileType!], $skipNginxValidation: Boolean) {\n  asyncPublishChanges(\n    profileTypes: $profileTypes\n    skipNginxValidation: $skipNginxValidation\n  )\n}\n",
    };
    const response = await fetch(WAF_GRAPHQL_URL, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        console.log("Changes published (async) successfully");
        const data = await response.json();
        return data?.data?.asyncPublishChanges;
    }
    console.error("Failed to publish changes");
    console.error("Error data:", await response.json());
    return null;
}

// Applies the published policy to the enforcement points. Returns an async
// task that is monitored with waitForTask().
async function enforcePolicy() {
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        operationName: "enforcePolicy",
        variables: {
            profileTypes: ["Docker", "CloudGuardAppSecGateway", "Embedded", "Kubernetes", "AppSecSaaS"],
        },
        query: "mutation enforcePolicy($profilesIds: [ID!], $profileTypes: [ProfileType!]) {\n  enforcePolicy(profilesIds: $profilesIds, profileTypes: $profileTypes) {\n    id\n    tenantId\n    type\n    status\n    startTime\n    endTime\n    message\n    errorCode\n    referenceId\n    __typename\n  }\n}\n",
    };
    const response = await fetch(WAF_GRAPHQL_URL, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        console.log("Policy enforced successfully");
        const data = await response.json();
        return data?.data?.enforcePolicy;
    }
    console.error("Failed to enforce policy");
    console.error("Error data:", await response.json());
    return null;
}

// Polls the task status with a fixed 2s backoff. Exits when the status is
// no longer InProgress.
async function waitForTask(taskId: string) {
    console.log("Waiting for taskId:", taskId);
    while (true) {
        const task = await getTask(taskId);
        const status = task?.status;
        console.log("Task status:", status);
        if (status !== "InProgress") break;
        await new Promise((resolve) => setTimeout(resolve, 2000));
    }
}

// Reads the status of an async task by its id.
async function getTask(taskid: string) {
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        variables: { id: taskid },
        query: "query getTask($id: ID!) {\n  getTask(id: $id) {\n    id\n    status\n    startTime\n  endTime\n   message\n    errorCode\n    referenceId\n    tenantId\n  }\n}\n",
    };
    const response = await fetch(WAF_GRAPHQL_URL, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        const data = await response.json();
        return data?.data?.getTask;
    }
    console.error("Failed to fetch task");
    console.error("Error data:", await response.json());
    return null;
}

// Combines publish + enforce + wait for task.
async function publishAndEnforce() {
    console.log("Publishing changes...");
    const publish = await asyncPublishChanges();
    console.log("Publish result:", publish);

    console.log("Enforcing policy...");
    const enforce = await enforcePolicy();
    console.log("Enforce result:", enforce);

    const taskId = enforce?.id;
    console.log("Task ID:", taskId);
    if (taskId) await waitForTask(taskId);
    return true;
}

// Asks the backend for the RSA public key used to encrypt the local AES key.
// sensitiveFieldName "nexusCertificate" identifies the kind of secret we are
// uploading; the backend returns the public key bound to that field.
async function getEncryptionPublicKey(profileId: string, region: string) {
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        operationName: "PublicKey",
        variables: {
            sensitiveFieldName: "nexusCertificate",
            profileId,
            region,
        },
        query: "query PublicKey($sensitiveFieldName: String!, $profileId: ID!, $region: String!) {\n  getPublicKey(\n    sensitiveFieldName: $sensitiveFieldName\n    profileId: $profileId\n    region: $region\n  )\n}\n",
    };
    const response = await fetch(WAF_GRAPHQL_URL, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        console.log("Public key fetched successfully");
        const data = await response.json();
        return data?.data?.getPublicKey;
    }
    console.error("Failed to fetch public key");
    console.error("Error data:", await response.json());
    return null;
}

// Hybrid AES-CBC + RSA-OAEP encryption. The steps are:
//   1. Generate a random AES-256 key + 16-byte IV (Web Crypto API).
//   2. Encrypt the cert's private key with AES-CBC.
//   3. Import the backend public key (SPKI/PEM format).
//   4. Encrypt the AES key with RSA-OAEP / SHA-256.
//   5. Return two base64 blobs:
//      - encryptedData = IV || ciphertext (AES)
//      - encryptedKey  = AES key encrypted with RSA
// Both blobs are sent to the backend; only Check Point can decrypt the
// first one because only they hold the matching RSA private key.
const encryptPrivateKey = async (privateKey: string, publicKeyPem: string) => {
    try {
        // 1. Fresh random material per certificate.
        const aesKey = crypto.getRandomValues(new Uint8Array(32));
        const iv = crypto.getRandomValues(new Uint8Array(16));

        const privateKeyBuffer = new TextEncoder().encode(privateKey);

        // 2. AES-CBC over the private key.
        const aesCryptoKey = await crypto.subtle.importKey("raw", aesKey, "AES-CBC", false, ["encrypt"]);
        const encryptedData = await crypto.subtle.encrypt(
            { name: "AES-CBC", iv },
            aesCryptoKey,
            privateKeyBuffer,
        );

        const encryptedDataBase64 = encodeBase64(new Uint8Array(encryptedData));
        const ivBase64 = encodeBase64(iv);

        // 3. Decode the public key PEM → SPKI binary.
        //    Strip header/footer and newlines, base64-decode the body.
        const pemHeader = "-----BEGIN PUBLIC KEY-----";
        const pemFooter = "-----END PUBLIC KEY-----";
        const pemContents = publicKeyPem
            .replace(pemHeader, "")
            .replace(pemFooter, "")
            .replace(/[\r\n]+/g, "");

        const binaryDer = Uint8Array.from(atob(pemContents), (c) => c.charCodeAt(0));

        // 4. Import the public key as RSA-OAEP / SHA-256.
        const publicKey = await crypto.subtle.importKey(
            "spki",
            binaryDer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["encrypt"],
        );

        // 5. Encrypt the AES key with RSA-OAEP.
        const encryptedAesKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, aesKey);
        const encryptedKeyBase64 = encodeBase64(new Uint8Array(encryptedAesKey));

        // The IV is concatenated to the start of the ciphertext (the
        // convention the backend expects) instead of being sent as a
        // separate field.
        return {
            encryptedData: ivBase64 + encryptedDataBase64,
            encryptedKey: encryptedKeyBase64,
        };
    } catch (error) {
        console.error(error);
        return { encryptedData: "", encryptedKey: "" };
    }
};

// Generates the timestamp suffix in the format the portal uses for the
// cert/key file names (e.g. "06-May-2026_18:30:42").
function portalTimestamp(): string {
    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const d = new Date();
    const dd = String(d.getDate()).padStart(2, "0");
    const mmm = months[d.getMonth()];
    const yyyy = d.getFullYear();
    const hh = String(d.getHours()).padStart(2, "0");
    const mi = String(d.getMinutes()).padStart(2, "0");
    const ss = String(d.getSeconds()).padStart(2, "0");
    return `${dd}-${mmm}-${yyyy}_${hh}:${mi}:${ss}`;
}

// Creates a SaaS BYOC (Bring Your Own Cert) certificate as a first-class
// object on the platform. Replaces the old addSensitiveField + the payload
// of updateDomainCertificate. Returns the certificateId of the new object.
//
// Notes about the input:
//   - certificateType "BYOC"  → own cert (not AWS-managed).
//   - encryptedFieldValue/Key → blobs from the hybrid encryption (encryptPrivateKey).
//   - certificate              → fullchain PEM IN CLEAR (the public part is not secret).
//   - certificateFile          → same PEM as a base64 data URL (the portal
//                                uses it to display/download the file).
//   - regions: array — allows multi-region for a single cert.
//   - domain: the cert is born linked to this domain; the explicit link
//     happens later via linkSaasCertificate.
async function createSaasCertificate(
    profileId: string,
    region: string,
    domain: string,
    encryptedFieldValue: string,
    encryptedKey: string,
    cert: string,
) {
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const ts = portalTimestamp();
    const certB64 = btoa(cert);
    const body = {
        operationName: "createSaasCertificate",
        variables: {
            certificateInput: {
                certificateType: "BYOC",
                encryptedFieldValue,
                encryptedKey,
                certificate: cert,
                certificateFile: `data:application/octet-stream;base64,${certB64}`,
                certFileName: `fullchain.pem_${ts}`,
                keyFileName: `privkey.pem_${ts}`,
                sensitiveFieldName: "nexusCertificate",
                profileId,
                regions: [region],
                domain,
            },
        },
        query: "mutation createSaasCertificate($certificateInput: CreateCertificateInput!) {\n  createSaasCertificate(certificateInput: $certificateInput) {\n    certificateId\n    __typename\n  }\n}\n",
    };
    const response = await fetch(WAF_GRAPHQL_URL, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        const data = await response.json();
        // The GraphQL API can return 200 OK with errors in data.errors.
        if (data?.errors) {
            console.error("createSaasCertificate returned errors:", data.errors);
            return null;
        }
        const certificateId = data?.data?.createSaasCertificate?.certificateId;
        console.log("SaaS certificate created. certificateId:", certificateId);
        return certificateId;
    }
    console.error("Failed to create SaaS certificate");
    console.error("Error data:", await response.json());
    return null;
}

// Links an existing certificate to a domain. Replaces the old
// updateDomainCertificate. The modern API works with two simple identifiers
// (domain + certificateId) instead of the old certificateParameter.id.
// This lets the same certificate (wildcard/SAN) be linked to several
// domains without re-uploads.
async function linkSaasCertificate(domain: string, certificateId: string) {
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        operationName: "linkSaasCertificate",
        variables: { domain, certificateId },
        query: "mutation linkSaasCertificate($domain: String!, $certificateId: ID!) {\n  linkSaasCertificate(domain: $domain, certificateId: $certificateId)\n}\n",
    };
    const response = await fetch(WAF_GRAPHQL_URL, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        const data = await response.json();
        if (data?.errors) {
            console.error("linkSaasCertificate returned errors:", data.errors);
            return null;
        }
        console.log(`Certificate ${certificateId} linked to domain ${domain}`);
        return data?.data?.linkSaasCertificate;
    }
    console.error("Failed to link SaaS certificate");
    console.error("Error data:", await response.json());
    return null;
}

// Discards the tenant draft. Rollback when publish fails.
async function discardChanges(): Promise<any> {
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        operationName: "discardChanges",
        variables: {},
        query: "mutation discardChanges {\n  discardChanges\n}\n",
    };
    try {
        const response = await fetch(WAF_GRAPHQL_URL, {
            method: "POST",
            headers,
            body: JSON.stringify(body),
        });
        if (response.ok) {
            console.log("Changes discarded successfully");
            const data = await response.json();
            return data?.data?.discardChanges;
        }
        console.error("Failed to discard changes");
        console.error("Error data:", await response.json());
    } catch (error) {
        console.error("Error discarding changes:", error);
    }
    return null;
}

// Append to a log file (errors are silently ignored to avoid breaking the
// main flow).
async function writeToFile(filePath: string, input: string) {
    try {
        await Deno.writeTextFile(filePath, input, { append: true });
    } catch (_error) { /* ignore */ }
}

async function main() {
    // Timestamped log in the current directory.
    const now = new Date();
    const formattedDate = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}-${String(now.getHours()).padStart(2, "0")}-${String(now.getMinutes()).padStart(2, "0")}`;
    FILEPATH = `./${formattedDate}_upload-certificates_output.log`;

    // 1. Load configuration (certificates.yaml) and credentials (.env).
    const config: any = await loadConfig("certificates.yaml");
    console.log("config:", JSON.stringify(config, null, 2));

    PROFILE = config.configuration.profile;
    REGION = config.configuration.region;
    console.log("Profile and Region loaded:", PROFILE, REGION);

    const url = Deno.env.get("WAFAUTHURL")!;
    const clientId = Deno.env.get("WAFKEY")!;
    const accessKey = Deno.env.get("WAFSECRET")!;

    // 2. Login + resolve the profile UUID.
    wafSession = await wafLogin(url, clientId, accessKey);
    if (!wafSession) {
        console.error("Failed to login to WAF");
        return;
    }

    PROFILE_PID = await wafProfiles();
    if (!PROFILE_PID) {
        console.error("Failed to get WAF profile ID");
        return;
    }

    if (!config?.urls) return;

    // 3. Loop over every URL — only create+link the certificate, do not
    //    publish yet. The anySuccess flag decides whether the final
    //    publish/enforce is worth running (large-batch optimization).
    let anySuccess = false;

    for (const asset of config.urls) {
        const assetDataInput = {
            ASSET_URL: asset.url,
            ASSET_DOMAIN: asset.domain,
            ASSET_CERT_PEM: asset.cert_pem,
            ASSET_CERT_KEY: asset.cert_key,
        };
        console.log("--------- URL ", assetDataInput.ASSET_URL, "started ---------");

        // 3a. Ask for a fresh public key per cert (it is cheap and lets the
        //     backend rotate without breaking us).
        const publicKey = await getEncryptionPublicKey(PROFILE_PID!, REGION!);
        if (!publicKey) {
            await writeToFile(FILEPATH, `Certificate upload failed (no public key) ${assetDataInput.ASSET_URL}\n`);
            continue;
        }

        // 3b. Read cert + key from disk. The key MUST have no passphrase
        //     and the cert MUST be fullchain (leaf cert + intermediates).
        const key = await Deno.readTextFile(assetDataInput.ASSET_CERT_KEY);
        const cert = await Deno.readTextFile(assetDataInput.ASSET_CERT_PEM);

        // 3c. Encrypt the private key (hybrid AES + RSA).
        const encrypted = await encryptPrivateKey(key, publicKey);
        if (!encrypted.encryptedData || !encrypted.encryptedKey) {
            await writeToFile(FILEPATH, `Certificate upload failed (encryption error) ${assetDataInput.ASSET_URL}\n`);
            continue;
        }
        console.log("Encrypted public key and private key");

        // 3d. Create the certificate object on the platform.
        const certificateId = await createSaasCertificate(
            PROFILE_PID!,
            REGION!,
            assetDataInput.ASSET_DOMAIN,
            encrypted.encryptedData,
            encrypted.encryptedKey,
            cert,
        );

        if (!certificateId) {
            await writeToFile(FILEPATH, `Certificate upload failed (createSaasCertificate) ${assetDataInput.ASSET_URL}\n`);
            console.log("--------- URL ", assetDataInput.ASSET_URL, "end ---------");
            continue;
        }

        // 3e. Link the certificate to the asset's domain.
        const linkResult = await linkSaasCertificate(assetDataInput.ASSET_DOMAIN, certificateId);
        if (linkResult === null) {
            await writeToFile(FILEPATH, `Certificate uploaded but link failed ${assetDataInput.ASSET_URL}\n`);
            console.log("--------- URL ", assetDataInput.ASSET_URL, "end ---------");
            continue;
        }

        await writeToFile(FILEPATH, `Certificate uploaded successfully ${assetDataInput.ASSET_URL}\n`);
        anySuccess = true;
        console.log("--------- URL ", assetDataInput.ASSET_URL, "end ---------");
    }

    // 4. Publish + enforce ONLY ONCE at the end, only if at least one
    //    certificate was uploaded. Large-batch optimization: avoids N
    //    unnecessary publish/enforce pairs when many certs are processed.
    if (anySuccess) {
        const ok = await publishAndEnforce();
        if (!ok) {
            console.error("Publish/enforce failed. Discarding changes...");
            await discardChanges();
        }
    } else {
        console.log("No certificates uploaded; skipping publish/enforce.");
    }
}

main()
    .then(() => console.log("done"))
    .catch((error) => console.error("Error:", error));
