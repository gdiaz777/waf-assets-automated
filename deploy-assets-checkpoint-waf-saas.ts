// ============================================================================
// deploy-assets-checkpoint-waf-saas.ts
// ----------------------------------------------------------------------------
// Despliega assets (aplicaciones web) en Check Point CloudGuard WAF SaaS /
// Infinity Next a partir del fichero assets.yaml. Soporta dos modos de
// certificado: cert propio (BYOC) y cert gestionado por el WAF (WAF_MANAGED).
//
// Optimización: la operación publishAndEnforce — costosa porque dispara la
// validación + propagación de la política a todo el data plane — se ejecuta
// UNA SOLA VEZ al final, después de crear todos los assets pendientes.
// ============================================================================

import { parse as parseYaml } from "jsr:@std/yaml";

// Endpoint GraphQL del Infinity Portal para el servicio WAF.
// La doble barra "//graphql" es la URL real que usa el portal — no es typo.
const WAF_GRAPHQL_URL = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql";

// Mapeo del flag "owncertificate" del YAML al valor del enum saasCertificateType
// que espera la API. "BYOC" está confirmado vía HAR. "WAF_MANAGED" es la
// hipótesis para el flujo gestionado — si Check Point lo rechaza, capturar un
// HAR creando un asset con cert AWS-managed y ajustar el valor aquí.
const SAAS_CERT_TYPE_BYOC = "BYOC";
const SAAS_CERT_TYPE_WAF_MANAGED = "WAF_MANAGED";

// Estado global del proceso. Se rellena al inicio de main() y se reusa en todas
// las funciones para no tener que pasar los mismos argumentos por todas partes.
let wafSession: any = null;     // Respuesta del login WAF (contiene el JWT en data.token).
let PROFILE: string | null = null;       // Nombre del profile AppSecSaaS objetivo.
let REGION: string | null = null;        // Región del profile (ej. "eu-west-1").
let PROFILE_PID: string | null = null;   // UUID del profile, resuelto en runtime a partir del nombre.
let FILEPATH: string | null = null;      // Ruta del log de salida con timestamp.

// Carga y parsea un fichero YAML. Devuelve null si el parseo falla.
async function loadConfig(filename: string) {
    const configText = await Deno.readTextFile(filename);
    try {
        return parseYaml(configText);
    } catch (error) {
        console.error("Error parsing YAML:", error);
        return null;
    }
}

// Login en el Infinity Portal. Recibe la URL de auth y las credenciales de la
// API key (servicio "Web Application & API Protection") y devuelve el objeto
// con el token JWT que se usará como Bearer en todas las llamadas siguientes.
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

// Resuelve el UUID del profile (PROFILE_PID) a partir de su nombre.
// Lista todos los profiles del tenant y filtra por la coincidencia exacta del
// nombre configurado en el YAML.
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

// Lista assets (aplicaciones web) usando la nueva query getWafAssets.
// El filtro class:["workload"] limita a assets de tipo aplicación, lo que
// reemplaza la antigua query AssetsName/getAssets que devolvía todos los
// objetos. matchSearch hace búsqueda parcial — luego se filtra por nombre
// exacto en el caller.
async function getWafAssets(matchSearch: string | undefined) {
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        operationName: "WafAssetsName",
        variables: {
            matchSearch: [matchSearch ?? ""],
            globalObject: false,
            paging: { offset: 0, limit: 50 },
            filters: { class: ["workload"] },
        },
        query: "query WafAssetsName($matchSearch: [String], $sortBy: SortBy, $globalObject: Boolean, $filters: AssetsFilter, $paging: Paging) {\n  getWafAssets(\n    matchSearch: $matchSearch\n    sortBy: $sortBy\n    globalObject: $globalObject\n    filters: $filters\n    paging: $paging\n  ) {\n    assets {\n      id\n      name\n      assetType\n      __typename\n    }\n    __typename\n  }\n}\n",
    };
    const response = await fetch(WAF_GRAPHQL_URL, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        console.log("Assets fetched successfully");
        const data = await response.json();
        return data?.data?.getWafAssets?.assets?.map((asset: any) => ({ id: asset.id, name: asset.name })) ?? [];
    }
    console.error("Failed to fetch assets");
    console.error("Error data:", await response.json());
    return null;
}

// Pre-flight de unicidad de nombre. Devuelve true si el nombre está libre.
// El portal lo llama antes del wizard para evitar errores en mid-create:
// es más barato fallar aquí que recibir un fallo a mitad de newAssetByWizard.
async function validateName(name: string): Promise<boolean> {
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        operationName: "validateName",
        variables: { name, type: "Asset" },
        query: "query validateName($name: String!, $type: ObjectType!) {\n  validateName(name: $name, type: $type)\n}\n",
    };
    const response = await fetch(WAF_GRAPHQL_URL, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
    });
    if (!response.ok) {
        console.error("validateName HTTP error", response.status);
        return false;
    }
    const data = await response.json();
    return data?.data?.validateName === true;
}

// Publica los cambios pendientes (asíncrono). Reemplaza al antiguo
// publishChanges (síncrono). Devuelve inmediatamente; la validación corre en
// background. La aplicación real al data plane la dispara enforcePolicy.
async function asyncPublishChanges() {
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        operationName: "asyncPublishChanges",
        variables: {
            // Tipos de profile cuyas configuraciones se publican. Incluimos
            // todos los tipos relevantes para el WAF SaaS para que un solo
            // publish cubra mixed deployments.
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

// Polling de estado del task con backoff fijo de 2s. Sale cuando el estado
// deja de ser InProgress (= Succeeded, Failed, etc.).
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

// Combina publish + enforce + espera al task. Si publish falla, se hace
// discardChanges() para dejar el draft del tenant limpio y no contaminar
// futuras ejecuciones.
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

// Crea un asset (aplicación web) vía wizard.
//   - ownCertificate: true  → BYOC (el cert se sube luego con upload-certificate-...)
//   - ownCertificate: false → WAF_MANAGED (cert auto-provisionado por Check Point)
//
// La diferencia entre ambos modos en la API es:
//   - assetInput.deployCertificateManually: true (BYOC) | false (WAF_MANAGED)
//   - profileInput.saasCertificateType:     "BYOC"      | "WAF_MANAGED"
async function newAssetByWizard(assetData: {
    name: string;
    domain: string[];
    upstream: string;
    region: string;
    profileId: string;
    profileName: string;
    ownCertificate: boolean;
}) {
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };

    const saasCertificateType = assetData.ownCertificate ? SAAS_CERT_TYPE_BYOC : SAAS_CERT_TYPE_WAF_MANAGED;

    const body = {
        operationName: "newAssetByWizard",
        variables: {
            assetType: "WebApplication",
            // Datos propios del asset (la aplicación web).
            assetInput: {
                name: assetData.name,
                URLs: assetData.domain,                  // Array de URLs https://...
                tags: [],
                stage: "Staging",                        // Estado de despliegue inicial
                // Campos AIGuard/LLM — vacíos cuando no aplica:
                uriPromptPairs: [],
                expectedPrompts: "wide",
                expectedUsers: "all",
                applicationDescription: "",
                llmModel: "",
                // Cómo identificar el cliente real detrás de un proxy/CDN:
                sourceIdentifiers: [{ sourceIdentifier: "XForwardedFor", values: [] }],
                deployCertificateManually: assetData.ownCertificate,
                state: "Active",
                upstreamURL: assetData.upstream,
            },
            // Datos del profile al que se asocia el asset.
            profileInput: {
                name: assetData.profileName,
                id: assetData.profileId,
                profileType: "AppSecSaaS",
                onlyDefinedApplications: false,
                // Campos para perfiles no-SaaS — null en SaaS:
                certificateType: null,
                vendor: null,
                isSelfManaged: false,
                region: assetData.region,
                saasCertificateType,                      // ← clave de la decisión BYOC vs WAF_MANAGED
            },
            zoneInput: {},
            // Política de fuentes para el behaviour engine.
            parameterInput: { numOfSources: 3, sourcesIdentifiers: [] },
            // Prácticas de seguridad por defecto. Mantienen los modos exactos
            // que aplica el wizard del portal.
            practiceInput: [
                {
                    practiceType: "WebApplication",
                    modes: [
                        { mode: "Learn", subPractice: "" },
                        { mode: "AccordingToPractice", subPractice: "WebAttacks" },
                        { mode: "AccordingToPractice", subPractice: "IPS" },
                    ],
                },
                {
                    practiceType: "APIProtection",
                    modes: [
                        { mode: "Disabled", subPractice: "" },
                        { mode: "Disabled", subPractice: "APIDiscovery" },
                        { mode: "Disabled", subPractice: "SchemaValidation" },
                        { mode: "Disabled", subPractice: "APIDiscovery" },
                    ],
                },
                {
                    // AIGuard se incluye desactivado por defecto — el portal lo
                    // envía aunque no haya configuración LLM, replicamos.
                    practiceType: "AIGuard",
                    modes: [
                        { mode: "Disabled", subPractice: "" },
                        { mode: "AccordingToPractice", subPractice: "PromptGuard" },
                        { mode: "AccordingToPractice", subPractice: "DataGuard" },
                        { mode: "AccordingToPractice", subPractice: "ContentGuard" },
                    ],
                },
            ],
            reportTriggerInput: {},
        },
        query: "mutation newAssetByWizard($assetType: AssetType!, $assetInput: wizardAssetInput!, $profileInput: wizardProfileInput!, $zoneInput: wizardZoneInput, $parameterInput: wizardParameterInput, $practiceInput: [wizardPracticeInput], $reportTriggerInput: wizardReportTriggerInput) {\n  newAssetByWizard(\n    assetType: $assetType\n    assetInput: $assetInput\n    profileInput: $profileInput\n    zoneInput: $zoneInput\n    parameterInput: $parameterInput\n    practiceInput: $practiceInput\n    reportTriggerInput: $reportTriggerInput\n  ) {\n    id\n    name\n    assetType\n    profiles {\n      id\n      name\n      __typename\n    }\n    practices {\n      practice {\n        id\n        category\n        __typename\n      }\n      triggers {\n        id\n        name\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n",
    };

    const response = await fetch(WAF_GRAPHQL_URL, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        const data = await response.json();
        // GraphQL puede devolver 200 OK con errores en data.errors.
        if (data?.errors) {
            console.error("newAssetByWizard returned errors:", data.errors);
            return null;
        }
        console.log("Asset created successfully");
        return data?.data?.newAssetByWizard;
    }
    console.error("Failed to create asset");
    console.error("Error data:", await response.json());
    return null;
}

// Wrapper de creación: traduce el formato del YAML al objeto que espera
// newAssetByWizard. Devuelve true si el asset se creó (para que main()
// pueda decidir si publicar al final), false si falló o se omitió.
async function createAsset(assetData: any): Promise<boolean> {
    const { ASSET_DOMAIN, ASSET_NAME, ASSET_CERTIFICATE_TYPE, ASSET_UPSTREAM } = assetData;

    const ownCertificate = ASSET_CERTIFICATE_TYPE === true;
    if (ASSET_CERTIFICATE_TYPE !== true && ASSET_CERTIFICATE_TYPE !== false) {
        console.error("No certificate type provided");
        return false;
    }

    const assetDataForNewAsset = {
        name: ASSET_NAME,
        domain: ASSET_DOMAIN,
        upstream: ASSET_UPSTREAM,
        region: REGION!,
        profileId: PROFILE_PID!,
        profileName: PROFILE!,
        ownCertificate,
    };
    console.log(
        ownCertificate
            ? "Adding new Asset with own (BYOC) certificate:"
            : "Adding new Asset with WAF-managed certificate:",
        assetDataForNewAsset,
    );

    const asset = await newAssetByWizard(assetDataForNewAsset);
    if (!asset) {
        await writeToFile(FILEPATH!, `FAIL to create Asset ${ASSET_NAME}\n`);
        return false;
    }

    console.log("Asset created with ID:", asset.id);
    await writeToFile(FILEPATH!, `Asset ${ASSET_NAME} created (id ${asset.id})\n`);
    return true;
}

// Descarta el draft de cambios del tenant. Se usa como rollback si publish
// falla, para no dejar configuración pendiente que afecte a futuras
// ejecuciones del script.
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

// Append a un fichero de log. Errores se ignoran silenciosamente para no
// romper el flujo principal por un problema de IO en el log.
async function writeToFile(filePath: string, input: string) {
    try {
        await Deno.writeTextFile(filePath, input, { append: true });
    } catch (_error) { /* ignore */ }
}

async function main() {
    // Log con timestamp de la ejecución, en el directorio actual.
    const now = new Date();
    const formattedDate = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}-${String(now.getHours()).padStart(2, "0")}-${String(now.getMinutes()).padStart(2, "0")}`;
    FILEPATH = `./${formattedDate}_deploy-assets_output.log`;

    // 1. Cargar configuración (assets.yaml) y credenciales (.env vía dotenvx).
    const config: any = await loadConfig("assets.yaml");
    console.log("config:", JSON.stringify(config, null, 2));

    PROFILE = config.configuration.profile;
    REGION = config.configuration.region;
    console.log("Profile and Region loaded:", PROFILE, REGION);

    const url = Deno.env.get("WAFAUTHURL")!;
    const clientId = Deno.env.get("WAFKEY")!;
    const accessKey = Deno.env.get("WAFSECRET")!;

    // 2. Login + resolver UUID del profile (una sola vez para todo el batch).
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

    if (!config?.assets) return;

    // 3. Bucle por cada asset del YAML — solo CREAR aquí, sin publicar todavía.
    //    Acumulamos el contador de creados; si alguno se creó disparamos un
    //    único publishAndEnforce al final (optimización para grandes cargas).
    let createdCount = 0;

    for (const asset of config.assets) {
        // El YAML permite varias URLs separadas por coma — las troceamos.
        const assetDomainsArray = asset.domain.split(",").map((d: string) => d.trim());
        const assetDataInput = {
            ASSET_DOMAIN: assetDomainsArray,
            ASSET_NAME: asset.name,
            ASSET_CERTIFICATE_TYPE: asset.owncertificate,
            ASSET_HOST: asset.host,
            ASSET_UPSTREAM: asset.upstream,
        };

        console.log("--------- ASSET ", assetDataInput.ASSET_NAME, "started ---------");

        // Idempotencia: si el asset ya existe con ese nombre, lo saltamos.
        const specificAsset = await getWafAssets(assetDataInput.ASSET_NAME);
        const matchingAsset = specificAsset?.find((a: any) => a.name === assetDataInput.ASSET_NAME);

        if (matchingAsset !== undefined) {
            console.log("Asset", matchingAsset.name, "already exists with ID", matchingAsset.id, "Skipping Asset");
            await writeToFile(FILEPATH, `Asset ${matchingAsset.name} already exists with ID ${matchingAsset.id}\n`);
        } else {
            // Pre-flight de unicidad antes de invocar el wizard. Si el nombre
            // ya está reservado por otro tipo de objeto, salta directamente.
            const nameFree = await validateName(assetDataInput.ASSET_NAME);
            if (!nameFree) {
                console.error(`Asset name "${assetDataInput.ASSET_NAME}" is not valid/unique. Skipping.`);
                await writeToFile(FILEPATH, `FAIL invalid name ${assetDataInput.ASSET_NAME}\n`);
            } else {
                console.log("NEW asset:", assetDataInput);
                const created = await createAsset(assetDataInput);
                if (created) createdCount++;
            }
        }
        console.log("--------- ASSET ", assetDataInput.ASSET_NAME, "end ---------");
    }

    // 4. Publish + enforce UNA SOLA VEZ al final, solo si hubo creaciones.
    //    Esta es la optimización para grandes cargas: evitamos N pares de
    //    publish/enforce innecesarios cuando se procesan muchos assets.
    if (createdCount > 0) {
        console.log(`========== Publishing ${createdCount} new asset(s) in a single batch ==========`);
        const ok = await publishAndEnforce();
        if (!ok) {
            console.error("Publish/enforce failed. Discarding changes...");
            await discardChanges();
            await writeToFile(FILEPATH, `BATCH publish/enforce FAILED for ${createdCount} asset(s)\n`);
        } else {
            await writeToFile(FILEPATH, `BATCH publish/enforce OK for ${createdCount} asset(s)\n`);
        }
    } else {
        console.log("No new assets created; skipping publish/enforce.");
    }
}

main()
    .then(() => console.log("done"))
    .catch((error) => console.error("Error:", error));
