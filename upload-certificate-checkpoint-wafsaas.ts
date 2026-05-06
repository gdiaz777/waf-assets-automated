// ============================================================================
// upload-certificate-checkpoint-wafsaas.ts
// ----------------------------------------------------------------------------
// Sube certificados SSL/TLS propios (BYOC) a Check Point CloudGuard WAF SaaS /
// Infinity Next y los enlaza a los dominios de assets que ya existen en el
// profile.
//
// Modelo de seguridad: la private key NUNCA viaja en claro. Se cifra
// localmente con AES-CBC; la clave AES se cifra con la public key RSA-OAEP
// que entrega el backend (cifrado híbrido). Solo Check Point puede descifrar
// con su private key, y solo entonces obtiene la AES key para abrir el blob.
//
// Optimización: publishAndEnforce se llama UNA SOLA VEZ al final, solo si al
// menos un certificado se subió correctamente.
// ============================================================================

import { encode as encodeBase64 } from "https://deno.land/std@0.208.0/encoding/base64.ts";
import { parse as parseYaml } from "jsr:@std/yaml";

// Endpoint GraphQL del Infinity Portal para WAF (la doble barra es real).
const WAF_GRAPHQL_URL = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql";

// Estado global del proceso. Se rellena en main() y se reusa en las funciones.
let wafSession: any = null;     // Respuesta del login (contiene el JWT en data.token).
let PROFILE: string | null = null;       // Nombre del profile AppSecSaaS objetivo.
let REGION: string | null = null;        // Región del profile.
let PROFILE_PID: string | null = null;   // UUID del profile.
let FILEPATH: string | null = null;      // Ruta del log de salida con timestamp.

// Carga y parsea un fichero YAML.
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

// Login en el Infinity Portal. Devuelve el objeto que contiene el JWT.
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

// Resuelve el UUID del profile a partir de su nombre (PROFILE).
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

// Publica los cambios del tenant (asíncrono). Reemplaza al antiguo
// publishChanges. La validación corre en background; la propagación al data
// plane la dispara enforcePolicy.
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

// Aplica la política publicada a los enforcement points. Devuelve un task
// asíncrono que se monitoriza con waitForTask().
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

// Polling del estado del task con backoff fijo de 2s. Sale cuando el estado
// deja de ser InProgress.
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

// Lee el estado de un task asíncrono por su id.
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

// Combina publish + enforce + espera al task.
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

// Pide al backend la public key RSA con la que cifrar la AES key local.
// sensitiveFieldName "nexusCertificate" identifica el tipo de secreto que
// vamos a subir; el backend devuelve la public key adecuada para ese campo.
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

// Cifrado híbrido AES-CBC + RSA-OAEP. Los pasos son:
//   1. Generar AES-256 key + IV de 16 bytes aleatorios (Web Crypto API).
//   2. Cifrar la private key del cert con AES-CBC.
//   3. Importar la public key del backend (formato SPKI/PEM).
//   4. Cifrar la AES key con RSA-OAEP / SHA-256.
//   5. Devolver dos blobs base64:
//      - encryptedData = IV || ciphertext (AES)
//      - encryptedKey  = AES key cifrada con RSA
// Ambos blobs viajan al backend; solo Check Point puede descifrar el primero
// porque solo ellos tienen la private key RSA emparejada.
const encryptPrivateKey = async (privateKey: string, publicKeyPem: string) => {
    try {
        // 1. Material aleatorio fresco para cada certificado.
        const aesKey = crypto.getRandomValues(new Uint8Array(32));
        const iv = crypto.getRandomValues(new Uint8Array(16));

        const privateKeyBuffer = new TextEncoder().encode(privateKey);

        // 2. AES-CBC sobre la private key.
        const aesCryptoKey = await crypto.subtle.importKey("raw", aesKey, "AES-CBC", false, ["encrypt"]);
        const encryptedData = await crypto.subtle.encrypt(
            { name: "AES-CBC", iv },
            aesCryptoKey,
            privateKeyBuffer,
        );

        const encryptedDataBase64 = encodeBase64(new Uint8Array(encryptedData));
        const ivBase64 = encodeBase64(iv);

        // 3. Decodificar la public key PEM → SPKI binario.
        //    Quitamos cabecera/pie y saltos de línea, base64-decode el cuerpo.
        const pemHeader = "-----BEGIN PUBLIC KEY-----";
        const pemFooter = "-----END PUBLIC KEY-----";
        const pemContents = publicKeyPem
            .replace(pemHeader, "")
            .replace(pemFooter, "")
            .replace(/[\r\n]+/g, "");

        const binaryDer = Uint8Array.from(atob(pemContents), (c) => c.charCodeAt(0));

        // 4. Importar la public key como RSA-OAEP / SHA-256.
        const publicKey = await crypto.subtle.importKey(
            "spki",
            binaryDer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["encrypt"],
        );

        // 5. Cifrar la AES key con RSA-OAEP.
        const encryptedAesKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, aesKey);
        const encryptedKeyBase64 = encodeBase64(new Uint8Array(encryptedAesKey));

        // El IV se concatena al inicio del ciphertext (convención esperada
        // por el backend) en lugar de enviarse como campo aparte.
        return {
            encryptedData: ivBase64 + encryptedDataBase64,
            encryptedKey: encryptedKeyBase64,
        };
    } catch (error) {
        console.error(error);
        return { encryptedData: "", encryptedKey: "" };
    }
};

// Genera el sufijo de timestamp con el formato que usa el portal para los
// nombres de fichero del cert/key (ej. "06-May-2026_18:30:42").
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

// Crea un certificado SaaS BYOC (Bring Your Own Cert) como objeto de primer
// nivel en la plataforma. Reemplaza al antiguo addSensitiveField + payload de
// updateDomainCertificate. Devuelve el certificateId del certificado creado.
//
// Notas sobre el input:
//   - certificateType "BYOC"  → cert propio (no AWS-managed).
//   - encryptedFieldValue/Key → blobs del cifrado híbrido (encryptPrivateKey).
//   - certificate              → fullchain PEM EN CLARO (la parte pública no es secreta).
//   - certificateFile          → mismo PEM en data URL base64 (el portal lo usa
//                                para mostrar/descargar el fichero).
//   - regions: array — permite multi-región para un mismo cert.
//   - domain: el cert nace ya asociado a este dominio; el link se hace luego.
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
        // La API GraphQL puede devolver 200 OK con errores en data.errors.
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

// Enlaza un certificado existente a un dominio. Reemplaza al antiguo
// updateDomainCertificate. La API moderna trabaja con dos identificadores
// simples (domain + certificateId) en lugar del antiguo certificateParameter.id.
// Esto permite que un mismo certificado (wildcard/SAN) se pueda enlazar a
// varios dominios sin reuploads.
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

// Descarta el draft del tenant. Rollback si publish falla.
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

// Append a fichero de log (errores se ignoran para no romper el flujo).
async function writeToFile(filePath: string, input: string) {
    try {
        await Deno.writeTextFile(filePath, input, { append: true });
    } catch (_error) { /* ignore */ }
}

async function main() {
    // Log con timestamp en el directorio actual.
    const now = new Date();
    const formattedDate = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}-${String(now.getHours()).padStart(2, "0")}-${String(now.getMinutes()).padStart(2, "0")}`;
    FILEPATH = `./${formattedDate}_upload-certificates_output.log`;

    // 1. Cargar configuración (certificates.yaml) y credenciales (.env).
    const config: any = await loadConfig("certificates.yaml");
    console.log("config:", JSON.stringify(config, null, 2));

    PROFILE = config.configuration.profile;
    REGION = config.configuration.region;
    console.log("Profile and Region loaded:", PROFILE, REGION);

    const url = Deno.env.get("WAFAUTHURL")!;
    const clientId = Deno.env.get("WAFKEY")!;
    const accessKey = Deno.env.get("WAFSECRET")!;

    // 2. Login + resolver UUID del profile.
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

    // 3. Bucle por cada URL — solo crear+enlazar el certificado, sin publicar
    //    aún. Usamos el flag anySuccess para decidir si vale la pena el
    //    publish/enforce final (optimización para grandes cargas).
    let anySuccess = false;

    for (const asset of config.urls) {
        const assetDataInput = {
            ASSET_URL: asset.url,
            ASSET_DOMAIN: asset.domain,
            ASSET_CERT_PEM: asset.cert_pem,
            ASSET_CERT_KEY: asset.cert_key,
        };
        console.log("--------- URL ", assetDataInput.ASSET_URL, "started ---------");

        // 3a. Pedir public key fresca por cada cert (es barato y permite
        //     que el backend rote sin rompernos).
        const publicKey = await getEncryptionPublicKey(PROFILE_PID!, REGION!);
        if (!publicKey) {
            await writeToFile(FILEPATH, `Certificate upload failed (no public key) ${assetDataInput.ASSET_URL}\n`);
            continue;
        }

        // 3b. Leer cert + key del disco. La key debe estar SIN passphrase y
        //     el cert debe ser fullchain (cert hoja + intermedios).
        const key = await Deno.readTextFile(assetDataInput.ASSET_CERT_KEY);
        const cert = await Deno.readTextFile(assetDataInput.ASSET_CERT_PEM);

        // 3c. Cifrar la private key (híbrido AES + RSA).
        const encrypted = await encryptPrivateKey(key, publicKey);
        if (!encrypted.encryptedData || !encrypted.encryptedKey) {
            await writeToFile(FILEPATH, `Certificate upload failed (encryption error) ${assetDataInput.ASSET_URL}\n`);
            continue;
        }
        console.log("Encrypted public key and private key");

        // 3d. Crear el objeto certificado en la plataforma.
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

        // 3e. Enlazar el certificado al dominio del asset.
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

    // 4. Publish + enforce UNA SOLA VEZ al final, solo si subimos al menos un
    //    certificado. Optimización para cargas grandes: evitamos N pares de
    //    publish/enforce innecesarios cuando se procesan muchos certs.
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
