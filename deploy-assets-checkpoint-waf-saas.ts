// ============================================================================
// deploy-assets-checkpoint-waf-saas.ts
// ----------------------------------------------------------------------------
// Deploys assets (web applications) to Check Point CloudGuard WAF SaaS /
// Infinity Next from the assets.yaml file. Supports two certificate modes:
// own certificate (BYOC) and Check Point–managed certificate (CPManaged).
//
// Optimization: publishAndEnforce — expensive because it triggers the
// validation + propagation of the policy to the whole data plane — is
// executed ONLY ONCE at the end, after creating all pending assets.
// ============================================================================

import { parse as parseYaml } from "jsr:@std/yaml";

// GraphQL endpoint of the Infinity Portal for the WAF service.
// The double slash "//graphql" is the actual URL the portal uses — not a typo.
const WAF_GRAPHQL_URL = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql";

// Mapping from the YAML "owncertificate" flag to the saasCertificateType
// enum expected by the API. Both values verified against the live API:
//   - "BYOC"      → Bring Your Own Certificate (uploaded later via the
//                   upload-certificate-... script).
//   - "CPManaged" → Check Point Managed certificate (auto-provisioned).
const SAAS_CERT_TYPE_BYOC = "BYOC";
const SAAS_CERT_TYPE_CP_MANAGED = "CPManaged";

// Global process state. Filled in at the start of main() and reused by all
// functions to avoid having to pass the same arguments around.
let wafSession: any = null;     // WAF login response (contains the JWT in data.token).
let PROFILE: string | null = null;       // Target AppSecSaaS profile name.
let REGION: string | null = null;        // Profile region (e.g. "eu-west-1").
let PROFILE_PID: string | null = null;   // Profile UUID, resolved at runtime from its name.
let FILEPATH: string | null = null;      // Output log path with timestamp.

// Loads and parses a YAML file. Returns null if parsing fails.
async function loadConfig(filename: string) {
    const configText = await Deno.readTextFile(filename);
    try {
        return parseYaml(configText);
    } catch (error) {
        console.error("Error parsing YAML:", error);
        return null;
    }
}

// Logs in to the Infinity Portal. Takes the auth URL and the API key
// credentials (service "Web Application & API Protection") and returns the
// object with the JWT used as Bearer in every subsequent call.
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

// Resolves the profile UUID (PROFILE_PID) from its name.
// Lists all profiles in the tenant and filters by exact name match against
// the value configured in the YAML.
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

// Lists assets (web applications) using the new getWafAssets query.
// The class:["workload"] filter restricts results to application-type assets,
// replacing the older AssetsName/getAssets query that returned every object.
// matchSearch performs a partial match — exact-name filtering is done by the
// caller.
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

// Name-uniqueness pre-flight. Returns true if the name is free.
// The portal calls this before the wizard to fail fast: it is cheaper to
// reject here than to receive a mid-create error from newAssetByWizard.
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

// Publishes pending changes (asynchronous). Replaces the old synchronous
// publishChanges. Returns immediately; validation runs in the background.
// Actual propagation to the data plane is triggered by enforcePolicy.
async function asyncPublishChanges() {
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        operationName: "asyncPublishChanges",
        variables: {
            // Profile types whose configurations get published. Including all
            // WAF SaaS-relevant types lets a single publish cover mixed
            // deployments.
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

// Polls the task status with a fixed 2s backoff. Exits when the status is no
// longer InProgress (i.e. Succeeded, Failed, etc.).
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

// Adds a Host header rewrite to a Web Application asset. Used when the
// upstream backend expects a different Host than the one the client used
// (e.g. clients hit "shop.example.com" but the upstream LB only matches
// "internal-shop.aws.example.com"). The portal stores this as two proxy
// setting items: isSetHeader=true plus setHeader="Host:<value>".
async function setHostHeader(assetId: string, hostHeader: string) {
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        operationName: "updateWebApplicationProxySetting",
        variables: {
            id: assetId,
            addProxySettingItems: [
                { key: "isSetHeader", value: "true" },
                { key: "setHeader", value: `Host:${hostHeader}` },
            ],
            updateProxySettingItems: [],
            removeProxySettingItems: [],
        },
        query: "mutation updateWebApplicationProxySetting($id: ID!, $addProxySettingItems: [WebApplicationProxySettingItemsInput], $removeProxySettingItems: [ID], $updateProxySettingItems: [WebApplicationProxySettingItemsUpdateInput]) {\n  updateWebApplicationProxySetting(\n    id: $id\n    addProxySettingItems: $addProxySettingItems\n    removeProxySettingItems: $removeProxySettingItems\n    updateProxySettingItems: $updateProxySettingItems\n  )\n}\n",
    };
    const response = await fetch(WAF_GRAPHQL_URL, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        const data = await response.json();
        if (data?.errors) {
            console.error("setHostHeader returned errors:", data.errors);
            return null;
        }
        console.log(`Host header set to "${hostHeader}" on asset ${assetId}`);
        return data?.data?.updateWebApplicationProxySetting;
    }
    console.error("Failed to set host header");
    console.error("Error data:", await response.json());
    return null;
}

// Combines publish + enforce + waiting for the task. If publish fails,
// discardChanges() is called to leave the tenant draft clean and avoid
// contaminating future executions.
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

// Creates an asset (web application) via the wizard.
//   - ownCertificate: true  → BYOC (the cert is uploaded later with upload-certificate-...)
//   - ownCertificate: false → CPManaged (cert auto-provisioned by Check Point)
//
// The difference between the two modes in the API is:
//   - assetInput.deployCertificateManually: true (BYOC) | false (CPManaged)
//   - profileInput.saasCertificateType:     "BYOC"      | "CPManaged"
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

    const saasCertificateType = assetData.ownCertificate ? SAAS_CERT_TYPE_BYOC : SAAS_CERT_TYPE_CP_MANAGED;

    const body = {
        operationName: "newAssetByWizard",
        variables: {
            assetType: "WebApplication",
            // Asset (web application) data.
            assetInput: {
                name: assetData.name,
                URLs: assetData.domain,                  // Array of https://... URLs
                tags: [],
                stage: "Staging",                        // Initial deployment stage
                // AIGuard/LLM fields — empty when not applicable:
                uriPromptPairs: [],
                expectedPrompts: "wide",
                expectedUsers: "all",
                applicationDescription: "",
                llmModel: "",
                // How to identify the real client behind a proxy/CDN:
                sourceIdentifiers: [{ sourceIdentifier: "XForwardedFor", values: [] }],
                deployCertificateManually: assetData.ownCertificate,
                state: "Active",
                upstreamURL: assetData.upstream,
            },
            // Data of the profile the asset is attached to.
            profileInput: {
                name: assetData.profileName,
                id: assetData.profileId,
                profileType: "AppSecSaaS",
                onlyDefinedApplications: false,
                // Fields used by non-SaaS profiles — null in SaaS:
                certificateType: null,
                vendor: null,
                isSelfManaged: false,
                region: assetData.region,
                saasCertificateType,                      // ← key driver of the BYOC vs CPManaged choice
            },
            zoneInput: {},
            // Source policy for the behaviour engine.
            parameterInput: { numOfSources: 3, sourcesIdentifiers: [] },
            // Default security practices. Mirrors exactly the modes the
            // portal wizard applies.
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
                    // AIGuard is included disabled by default — the portal
                    // sends it even when there is no LLM configuration, we
                    // mirror that.
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
        // GraphQL can return 200 OK with errors in data.errors.
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

// Creation wrapper: translates the YAML format into the object expected by
// newAssetByWizard. After successful creation, applies the optional Host
// header rewrite via setHostHeader. Returns true if the asset was created
// (so main() can decide whether to publish at the end), false if it failed
// or was skipped.
async function createAsset(assetData: any): Promise<boolean> {
    const { ASSET_DOMAIN, ASSET_NAME, ASSET_CERTIFICATE_TYPE, ASSET_UPSTREAM, ASSET_HOST } = assetData;

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

    // Optional Host header rewrite. Only invoked when the YAML supplies a
    // host value. A failure here does not undo the asset creation — the
    // asset is logged as created and the host failure is logged separately.
    if (ASSET_HOST) {
        const headerResult = await setHostHeader(asset.id, ASSET_HOST);
        if (headerResult === null) {
            await writeToFile(FILEPATH!, `Asset ${ASSET_NAME} created but Host header FAILED\n`);
        } else {
            await writeToFile(FILEPATH!, `Asset ${ASSET_NAME} created (id ${asset.id}) with Host=${ASSET_HOST}\n`);
        }
    } else {
        await writeToFile(FILEPATH!, `Asset ${ASSET_NAME} created (id ${asset.id})\n`);
    }
    return true;
}

// Discards the tenant change draft. Used as a rollback when publish fails so
// no dangling configuration affects subsequent script runs.
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

// Append to a log file. Errors are silently ignored to avoid breaking the
// main flow because of an IO problem on the log.
async function writeToFile(filePath: string, input: string) {
    try {
        await Deno.writeTextFile(filePath, input, { append: true });
    } catch (_error) { /* ignore */ }
}

async function main() {
    // Timestamped run log in the current directory.
    const now = new Date();
    const formattedDate = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}-${String(now.getHours()).padStart(2, "0")}-${String(now.getMinutes()).padStart(2, "0")}`;
    FILEPATH = `./${formattedDate}_deploy-assets_output.log`;

    // 1. Load configuration (assets.yaml) and credentials (.env via dotenvx).
    const config: any = await loadConfig("assets.yaml");
    console.log("config:", JSON.stringify(config, null, 2));

    PROFILE = config.configuration.profile;
    REGION = config.configuration.region;
    console.log("Profile and Region loaded:", PROFILE, REGION);

    const url = Deno.env.get("WAFAUTHURL")!;
    const clientId = Deno.env.get("WAFKEY")!;
    const accessKey = Deno.env.get("WAFSECRET")!;

    // 2. Login + resolve profile UUID (only once for the whole batch).
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

    // 3. Loop over every asset in the YAML — only CREATE here, do not publish
    //    yet. We accumulate the count of created assets; if at least one was
    //    created we trigger a single publishAndEnforce at the end (large-batch
    //    optimization).
    let createdCount = 0;

    for (const asset of config.assets) {
        // The YAML allows several URLs separated by comma — split them.
        const assetDomainsArray = asset.domain.split(",").map((d: string) => d.trim());
        const assetDataInput = {
            ASSET_DOMAIN: assetDomainsArray,
            ASSET_NAME: asset.name,
            ASSET_CERTIFICATE_TYPE: asset.owncertificate,
            ASSET_HOST: asset.host,
            ASSET_UPSTREAM: asset.upstream,
        };

        console.log("--------- ASSET ", assetDataInput.ASSET_NAME, "started ---------");

        // Idempotency: if an asset with that name already exists, skip it.
        const specificAsset = await getWafAssets(assetDataInput.ASSET_NAME);
        const matchingAsset = specificAsset?.find((a: any) => a.name === assetDataInput.ASSET_NAME);

        if (matchingAsset !== undefined) {
            console.log("Asset", matchingAsset.name, "already exists with ID", matchingAsset.id, "Skipping Asset");
            await writeToFile(FILEPATH, `Asset ${matchingAsset.name} already exists with ID ${matchingAsset.id}\n`);
        } else {
            // Uniqueness pre-flight before invoking the wizard. If the name
            // is already reserved by another object type, skip immediately.
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

    // 4. Publish + enforce ONLY ONCE at the end, only if anything was created.
    //    This is the large-batch optimization: it avoids N unnecessary
    //    publish/enforce pairs when many assets are processed.
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
