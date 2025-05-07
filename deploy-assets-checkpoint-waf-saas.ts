import { encode as encodeBase64 } from "https://deno.land/std@0.208.0/encoding/base64.ts";
import { parse as parseYaml } from "jsr:@std/yaml";

let wafSession = null
let PROFILE = null
let REGION = null
let PROFILE_PID = null
let FILEPATH = null

// Load the configuration file
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

// Function to login to WAF
async function wafLogin(url: string, clientId: string, accessKey: string) {
    try {
        const response = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ clientId, accessKey }),
        });

        if (response.ok) {
            console.log("Login successful");
            const data = await response.json();
            return data;
        } else {
            console.error("Login failed with status:", response.status);
            const errorData = await response.json();
            console.error("Error details:", errorData);
        }
    } catch (error) {
        console.error("Error during WAF login:", error);
    }

    return null;
}
// WAF profile
async function wafProfiles() {
    const url = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql";
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        "operationName": "ProfilesName",
        "variables": {},
        "query": "query ProfilesName($matchSearch: String, $filters: ProfileFilter, $paging: Paging, $sortBy: SortBy) {\n  getProfiles(\n    matchSearch: $matchSearch\n    filters: $filters\n    paging: $paging\n    sortBy: $sortBy\n  ) {\n    id\n    name\n    __typename\n  }\n}\n"
    };
    try {
        const response = await fetch(url, {
            method: "POST",
            headers: headers,
            body: JSON.stringify(body),
        });
        if (response.ok) {
            const data = await response.json();
            const profiles = data?.data?.getProfiles.map((profile: any) => ({
                id: profile.id,
                name: profile.name,
            })) || [];
            console.log("Profiles fetched successfully:", profiles);

            if (profiles.length > 0) {
                const matchingProfile = profiles.find((profile: any) => profile.name === PROFILE);
                if (matchingProfile) {
                    console.log(`Matching profile found: ${matchingProfile.name} with ID ${matchingProfile.id}`);
                    return matchingProfile.id; // Return the id of the matching profile
                } else {
                    console.error(`No profile found with the name "${PROFILE}"`);
                }
            } else {
                console.error("No profiles available.");
            }
        } else {
            console.error("Failed to fetch profiles. Status:", response.status);
            const errorData = await response.json();
            console.error("Error details:", errorData);
        }
    } catch (error) {
        console.error("Error during fetching profiles:", error);
    }

    return null; 
}

//get assets
async function getAssets(matchSearch: string | undefined) {
    const url = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql";
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        "operationName": "AssetsName",
        "variables": {
            "matchSearch": [
                matchSearch ? matchSearch : ""
            ],
            "globalObject": false,
            "paging": {
                "offset": 0,
                "limit": 50
            },
            "filters": {}
        },
        "query": "query AssetsName($matchSearch: [String], $sortBy: SortBy, $globalObject: Boolean, $filters: AssetsFilter, $paging: Paging) {\n  getAssets(\n    matchSearch: $matchSearch\n    sortBy: $sortBy\n    globalObject: $globalObject\n    filters: $filters\n    paging: $paging\n  ) {\n    assets {\n      id\n      name\n      assetType\n      __typename\n    }\n    __typename\n  }\n}\n"
    };
    const response = await fetch(url, {
        method: "POST",
        headers: headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        console.log("Assets fetched successfully");
        const data = await response.json();
        //console.log("data:", data);
        return data?.data?.getAssets?.assets?.map((asset: any) => ({
            id: asset.id,
            name: asset.name,
        })) || [];
    } else {
        console.error("Failed to fetch assets");
        const errorData = await response.json();
        console.error("Error data:", errorData);
    }
    return null
}

//publish changes
async function publishChanges() {
    const url = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql";
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        "operationName": "publishChanges",
        "variables": {
            "profileTypes": [
                "Docker",
                "CloudGuardAppSecGateway",
                "Embedded",
                "Kubernetes",
                "AppSecSaaS"
            ]
        },
        "query": "mutation publishChanges($profileTypes: [ProfileType!], $skipNginxValidation: Boolean) {\n  publishChanges(\n    profileTypes: $profileTypes\n    skipNginxValidation: $skipNginxValidation\n  ) {\n    isValid\n    errors {\n      message\n      __typename\n    }\n    warnings {\n      message\n      __typename\n    }\n    isNginxErrors\n    __typename\n  }\n}\n"

    }

    const response = await fetch(url, {
        method: "POST",
        headers: headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        console.log("Changes published successfully");
        const data = await response.json();
        // console.log("data:", data);
        return data?.data?.publishChanges;
    } else {
        console.error("Failed to publish changes");
        const errorData = await response.json();
        console.error("Error data:", errorData);
    }
    return null
}

//enforce policy
async function enforcePolicy() {
    const url = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql";
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        "operationName": "enforcePolicy",
        "variables": {
            "profileTypes": [
                "Docker",
                "CloudGuardAppSecGateway",
                "Embedded",
                "Kubernetes",
                "AppSecSaaS"
            ]
        },
        "query": "mutation enforcePolicy($profilesIds: [ID!], $profileTypes: [ProfileType!]) {\n  enforcePolicy(profilesIds: $profilesIds, profileTypes: $profileTypes) {\n    id\n    tenantId\n    type\n    status\n    startTime\n    endTime\n    message\n    errorCode\n    referenceId\n    __typename\n  }\n}\n"
    }
    const response = await fetch(url, {
        method: "POST",
        headers: headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        console.log("Policy enforced successfully");
        const data = await response.json();
        // console.log("data:", data);
        return data?.data?.enforcePolicy;
    } else {
        console.error("Failed to enforce policy");
        const errorData = await response.json();
        console.error("Error data:", errorData);
    }
    return null
}

//wait for task
async function waitForTask(taskId: string) {
    console.log("Waiting for taskId:", taskId);
    while (true) {
        const task = await getTask(taskId!)
        // console.log("task:", task);
        const status = task?.status
        console.log("Task status:", status);
        if (status !== "InProgress") {
            // console.log("Task status:", status);
            break;
        }
        // sleep for 2 seconds
        await new Promise((resolve) => setTimeout(resolve, 2000));
    }

}

//get task
async function getTask(taskid: string) {
    const url = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql";
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        "variables": {
            "id": taskid
        },
        "query": "query getTask($id: ID!) {\n  getTask(id: $id) {\n    id\n    status\n    startTime\n  endTime\n   message\n    errorCode\n    referenceId\n    tenantId\n  }\n}\n"
    }
    const response = await fetch(url, {
        method: "POST",
        headers: headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        console.log("Task fetched successfully");
        const data = await response.json();
        // console.log("data:", data);
        return data?.data?.getTask;
    }
    else {
        console.error("Failed to fetch task");
        const errorData = await response.json();
        console.error("Error data:", errorData);
    }
    return null
}

//publish and enforce
async function publishAndEnforce() {
    console.log("Publishing changes...");
    const publish = await publishChanges();
    console.log("Publish result:", publish);

    // Check if publish is valid
    if (publish?.isValid === false) {
        console.error("Publish failed. Discarding changes...");
        const discardResult = await discardChanges();
        console.log("Discard changes result:", discardResult);
        return false; // Exit the function if publish is invalid
    }

    console.log("Enforcing policy...");
    const enforce = await enforcePolicy();
    console.log("Enforce result:", enforce);

    const taskId = enforce?.id;
    console.log("Task ID:", taskId);
    if (taskId) {
        await waitForTask(taskId);
    }
    return true;
}

// New asset
async function newAssetOwnCert(assetData: { name: string, domain: string, upstream: string, region: string, profileId: string, profileName: string }) {
    const url = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql";
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        "operationName": "newAssetByWizard",
        "variables": {
            "assetType": "WebApplication",
            "assetInput": {
                "name": assetData.name,
                "URLs": assetData.domain,
                "tags": [],
                "stage": "Staging",
                "sourceIdentifiers": [
                    {
                        "sourceIdentifier": "XForwardedFor",
                        "values": []
                    }
                ],
                "deployCertificateManually": true,
                "state": "Active",
                "upstreamURL": assetData.upstream
            },
            "profileInput": {
                "name": assetData.profileName,
                "id": assetData.profileId,
                "profileType": "AppSecSaaS",
                "isCertificateUploadRequired": true,
                "region": assetData.region
            },
            "zoneInput": {},
            "parameterInput": {
                "numOfSources": 3,
                "sourcesIdentifiers": []
              },
              "practiceInput": [
                {
                  "practiceType": "WebApplication",
                  "modes": [
                    {
                      "mode": "Learn",
                      "subPractice": ""
                    },
                    {
                      "mode": "AccordingToPractice",
                      "subPractice": "WebAttacks"
                    },
                    {
                      "mode": "AccordingToPractice",
                      "subPractice": "IPS"
                    }
                  ]
                },
                {
                  "practiceType": "APIProtection",
                  "modes": [
                    {
                      "mode": "Disabled",
                      "subPractice": ""
                    },
                    {
                      "mode": "Disabled",
                      "subPractice": "APIDiscovery"
                    },
                    {
                      "mode": "AccordingToPractice",
                      "subPractice": "SchemaValidation"
                    }
                  ]
                }
              ],
              "reportTriggerInput": {}
            // Add other inputs as needed
        },
        "query": "mutation newAssetByWizard($assetType: AssetType!, $assetInput: wizardAssetInput!, $profileInput: wizardProfileInput!, $zoneInput: wizardZoneInput, $parameterInput: wizardParameterInput, $practiceInput: [wizardPracticeInput], $reportTriggerInput: wizardReportTriggerInput) {\n  newAssetByWizard(\n    assetType: $assetType\n    assetInput: $assetInput\n    profileInput: $profileInput\n    zoneInput: $zoneInput\n    parameterInput: $parameterInput\n    practiceInput: $practiceInput\n    reportTriggerInput: $reportTriggerInput\n  ) {\n    id\n    name\n    assetType\n    profiles {\n      id\n      name\n      __typename\n    }\n    practices {\n      practice {\n        id\n        category\n        __typename\n      }\n      triggers {\n        id\n        name\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"
    };
    const response = await fetch(url, {
        method: "POST",
        headers: headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        console.log("Asset created successfully");
        const data = await response.json();
        return data?.data?.newAssetByWizard;
    }
    else {
        console.error("Failed to create asset");
        const errorData = await response.json();
        console.error("Error data:", errorData);
    }
    return null
}

async function newAssetAWSCert(assetData: { name: string, domain: string, upstream: string, region: string, profileId: string, profileName: string }) {
    const url = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql";
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        "operationName": "newAssetByWizard",
        "variables": {
            "assetType": "WebApplication",
            "assetInput": {
                "name": assetData.name,
                "URLs": assetData.domain,
                "tags": [],
                "stage": "Staging",
                "sourceIdentifiers": [
                    {
                        "sourceIdentifier": "XForwardedFor",
                        "values": []
                    }
                ],
                "deployCertificateManually": false,
                "state": "Active",
                "upstreamURL": assetData.upstream
            },
            "profileInput": {
                "name": assetData.profileName,
                "id": assetData.profileId,
                "profileType": "AppSecSaaS",
                "isCertificateUploadRequired": false,
                "region": assetData.region
            },
            "zoneInput": {},
            "parameterInput": {
                "numOfSources": 3,
                "sourcesIdentifiers": []
              },
              "practiceInput": [
                {
                  "practiceType": "WebApplication",
                  "modes": [
                    {
                      "mode": "Learn",
                      "subPractice": ""
                    },
                    {
                      "mode": "AccordingToPractice",
                      "subPractice": "WebAttacks"
                    },
                    {
                      "mode": "AccordingToPractice",
                      "subPractice": "IPS"
                    }
                  ]
                },
                {
                  "practiceType": "APIProtection",
                  "modes": [
                    {
                      "mode": "Disabled",
                      "subPractice": ""
                    },
                    {
                      "mode": "Disabled",
                      "subPractice": "APIDiscovery"
                    },
                    {
                      "mode": "AccordingToPractice",
                      "subPractice": "SchemaValidation"
                    }
                  ]
                }
              ],
              "reportTriggerInput": {}
            // Add other inputs as needed
        },
        "query": "mutation newAssetByWizard($assetType: AssetType!, $assetInput: wizardAssetInput!, $profileInput: wizardProfileInput!, $zoneInput: wizardZoneInput, $parameterInput: wizardParameterInput, $practiceInput: [wizardPracticeInput], $reportTriggerInput: wizardReportTriggerInput) {\n  newAssetByWizard(\n    assetType: $assetType\n    assetInput: $assetInput\n    profileInput: $profileInput\n    zoneInput: $zoneInput\n    parameterInput: $parameterInput\n    practiceInput: $practiceInput\n    reportTriggerInput: $reportTriggerInput\n  ) {\n    id\n    name\n    assetType\n    profiles {\n      id\n      name\n      __typename\n    }\n    practices {\n      practice {\n        id\n        category\n        __typename\n      }\n      triggers {\n        id\n        name\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"
    };
    const response = await fetch(url, {
        method: "POST",
        headers: headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        console.log("Asset created successfully");
        const data = await response.json();
        return data?.data?.newAssetByWizard;
    }
    else {
        console.error("Failed to create asset");
        const errorData = await response.json();
        console.error("Error data:", errorData);
    }
    return null
}

//create asset
async function createAsset(assetData: any) {

    const { ASSET_DOMAIN, ASSET_NAME, ASSET_CERTIFICATE_TYPE, ASSET_HOST, ASSET_UPSTREAM } = assetData;
    const url = Deno.env.get("WAFAUTHURL")!;
    const clientId = Deno.env.get("WAFKEY")!;
    const accessKey = Deno.env.get("WAFSECRET")!;

    const thisregion = REGION;
    const thisprofile = PROFILE;
    const thisprofilepid = PROFILE_PID;

    const assetDataForNewAsset = {
        name: ASSET_NAME,
        domain: ASSET_DOMAIN,
        upstream: ASSET_UPSTREAM,
        region: thisregion,
        profileId: thisprofilepid,
        profileName: thisprofile,
    }
    console.log("Adding new Asset with following characteristic:", assetDataForNewAsset);

    if (ASSET_CERTIFICATE_TYPE === true) {
        const asset = await newAssetOwnCert(assetDataForNewAsset)
        const assetId = asset?.id;
        console.log("Asset created with ID:", assetId);
        const resultpublish = await publishAndEnforce();
        if (resultpublish === false) {
            await writeToFile(FILEPATH, `FAIL to create Asset ${ASSET_NAME} \n`);
            return;
        }
        await writeToFile(FILEPATH, `Asset ${ASSET_NAME} created successfully \n`);
    } else if (ASSET_CERTIFICATE_TYPE === false) {
        console.log("Certificate will be created with AWS certificate.");
        const asset = await newAssetAWSCert(assetDataForNewAsset)
        const assetId = asset?.id;
        console.log("Asset created with ID:", assetId);
        const resultpublish = await publishAndEnforce();
       
        if (resultpublish === false) {
            await writeToFile(FILEPATH, `FAIL to create Asset ${ASSET_NAME} \n`);
            return;
        }
        await writeToFile(FILEPATH, `Asset ${ASSET_NAME} created successfully \n`);
    } else {
        console.error("No certificate type provided");
        return;
    }
}

//discard changes
async function discardChanges(): Promise<any> {
    const url = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql";
    const token = wafSession?.data?.token; // Ensure wafSession is initialized
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };

    const body = {
        "operationName": "discardChanges",
        "variables": {},
        "query": "mutation discardChanges {\n  discardChanges\n}\n"
    };

    try {
        const response = await fetch(url, {
            method: "POST",
            headers: headers,
            body: JSON.stringify(body),
        });

        if (response.ok) {
            console.log("Changes discarded successfully");
            const data = await response.json();
            return data?.data?.discardChanges;
        } else {
            console.error("Failed to discard changes");
            const errorData = await response.json();
            console.error("Error data:", errorData);
        }
    } catch (error) {
        console.error("Error discarding changes:", error);
    }

    return null;
}

//write log
async function writeToFile(filePath: string, input: string) {
    try {
        await Deno.writeTextFile(filePath, input, { append: true }); // Append to the file
    } catch (error) {
    }
}

async function main() {
   
    // Create output file
    const now = new Date();
    const formattedDate = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}-${String(now.getHours()).padStart(2, "0")}-${String(now.getMinutes()).padStart(2, "0")}`;
    FILEPATH = `./${formattedDate}_deploy-assets_output.log`; // File path with the formatted date
        
    //Load configuration    
    const config = await loadConfig("assets.yaml");
    console.log("config:", JSON.stringify(config, null, 2));
    
    //Load Profile and Region.
     PROFILE = config.configuration.profile;
     REGION = config.configuration.region;
     console.log("Profile and Region loaded:", PROFILE, REGION);

    //Load WAF credentials.
    const url = Deno.env.get("WAFAUTHURL")!;
    const clientId = Deno.env.get("WAFKEY")!;
    const accessKey = Deno.env.get("WAFSECRET")!;
    
    //Login WAF and save the session into wafSession variable.
    wafSession = await wafLogin(url, clientId, accessKey);
    if (!wafSession) {
        console.error("Failed to login to WAF");
        return;
    }

    // Get the WAF profile ID
    PROFILE_PID = await wafProfiles();
    if (!PROFILE_PID) {
        console.error("Failed to get WAF profile ID");
        return;
    }

    //Load assets configuration.
     if (config?.assets) {
        // Loop through each asset in the configuration
        for (const asset of config.assets) {
            const assetDomainsArray = asset.domain.split(",").map(domain => domain.trim());
            const assetDataInput = {
                ASSET_DOMAIN: assetDomainsArray,
                ASSET_NAME: asset.name,
                ASSET_CERTIFICATE_TYPE: asset.owncertificate, 
                ASSET_HOST: asset.host,
                ASSET_UPSTREAM: asset.upstream
            };     
            
            console.log("--------- ASSET ", assetDataInput.ASSET_NAME ,"started ---------");
            // Get the asset name and the asset id from a specific domain.
            const specificAsset = await getAssets(assetDataInput.ASSET_NAME);
            const matchingAsset = specificAsset.find((specificAsset: any) => specificAsset.name === assetDataInput.ASSET_NAME);
            // Check if the asset already exists and has the same domain as the configuration.
            if (matchingAsset !== undefined) {
                const assetId= matchingAsset.id;
                const assetName = matchingAsset.name;
                console.log("Asset", assetName, "already exists with ID ",assetId, "Skipping Asset");
                await writeToFile(FILEPATH, `Asset ${assetName} already exists with ID ${assetId}\n`);

            }else{
                console.log("NEW asset:", assetDataInput);
                await createAsset(assetDataInput);
            }
        console.log("--------- ASSET ", assetDataInput.ASSET_NAME ,"end ---------");
        }
    }
    //await dnsRecords();
    return;

}


main()
    .then(() => {
        console.log("done");
    })
    .catch((error) => {
        console.error("Error:", error);
    });