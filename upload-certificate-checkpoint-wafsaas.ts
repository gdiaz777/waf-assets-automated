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

//get encryption public key
async function getEncryptionPublicKey(profileId: string, region: string) {
    const url = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql";
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        "operationName": "PublicKey",
        "variables": {
            "sensitiveFieldName": "nexusCertificate",
            "profileId": profileId,
            "region": region
        },
        "query": "query PublicKey($sensitiveFieldName: String!, $profileId: ID!, $region: String!) {\n  getPublicKey(\n    sensitiveFieldName: $sensitiveFieldName\n    profileId: $profileId\n    region: $region\n  )\n}\n"
    }
    const response = await fetch(url, {
        method: "POST",
        headers: headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        console.log("Public key fetched successfully");
        const data = await response.json();
        // console.log("data:", data);
        return data?.data?.getPublicKey;
    }
    else {
        console.error("Failed to fetch public key");
        const errorData = await response.json();
        console.error("Error data:", errorData);
    }
    return null
}

//encrypt private key
const encryptPrivateKey = async (privateKey: string, publicKeyPem: string) => {
    try {
        // Generate random bytes for AES key and IV
        const aesKey = crypto.getRandomValues(new Uint8Array(32));
        const iv = crypto.getRandomValues(new Uint8Array(16));

        // Create a buffer from the private key
        const privateKeyBuffer = new TextEncoder().encode(privateKey);

        // Import the AES key
        const aesCryptoKey = await crypto.subtle.importKey(
            "raw",
            aesKey,
            "AES-CBC",
            false,
            ["encrypt"]
        );

        // Encrypt the private key using AES-CBC
        const encryptedData = await crypto.subtle.encrypt(
            {
                name: "AES-CBC",
                iv: iv,
            },
            aesCryptoKey,
            privateKeyBuffer
        );

        const encryptedDataBase64 = encodeBase64(new Uint8Array(encryptedData));
        const ivBase64 = encodeBase64(iv);


        // Remove the PEM header and footer
        const pemHeader = "-----BEGIN PUBLIC KEY-----";
        const pemFooter = "-----END PUBLIC KEY-----";
        const pemContents = publicKeyPem
            .replace(pemHeader, "")
            .replace(pemFooter, "")
            .replace(/[\r\n]+/g, ""); // Remove newlines

        // Decode the base64 content
        const binaryDer = Uint8Array.from(atob(pemContents), c =>
            c.charCodeAt(0)
        );

        // Import the public key
        const publicKey = await crypto.subtle.importKey(
            "spki",
            binaryDer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256",
            },
            false,
            ["encrypt"]
        );

        // Encrypt the AES key using the provided public key (RSA-OAEP)
        const encryptedAesKey = await crypto.subtle.encrypt(
            {
                name: "RSA-OAEP",
            },
            publicKey,
            aesKey
        );

        const encryptedKeyBase64 = encodeBase64(new Uint8Array(encryptedAesKey));

        return {
            encryptedData: ivBase64 + encryptedDataBase64,
            encryptedKey: encryptedKeyBase64,
        };
    } catch (error) {
        console.error(error);
        return {
            encryptedData: "",
            encryptedKey: "",
        };
    }
};

//add sensitive field
async function addSensitiveField(profileId: string, region: string, encryptedFieldValue: string, encryptedKey: string, cert: string) {
    const url = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql";
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        "operationName": "addSensitiveField",
        "variables": {
            "sensitiveFieldName": "nexusCertificate",
            "encryptedFieldValue": encryptedFieldValue,
            "encryptedKey": encryptedKey,
            "certificate": cert,
            "profileId": profileId,
            "region": region
        },
        "query": "mutation addSensitiveField($sensitiveFieldName: String!, $encryptedFieldValue: String!, $encryptedKey: String!, $certificate: String!, $profileId: ID!, $region: String!) {\n  addSensitiveField(\n    sensitiveFieldName: $sensitiveFieldName\n    encryptedFieldValue: $encryptedFieldValue\n    encryptedKey: $encryptedKey\n    certificate: $certificate\n    profileId: $profileId\n    region: $region\n  ) {\n    certificateARNForCloudfront\n    certificateArn\n    __typename\n  }\n}\n"
    }
    const response = await fetch(url, {
        method: "POST",
        headers: headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        console.log("Sensitive field added successfully");
        const data = await response.json();
        // console.log("data:", data);
        return data?.data?.addSensitiveField;
    }
    else {
        console.error("Failed to add sensitive field");
        const errorData = await response.json();
        console.error("Error data:", errorData);
    }
    return null
}

//get profile
async function getProfile(profileId: string) {
    const url = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql";
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const body = {
        "operationName": "Profile",
        "variables": {
            "id": profileId
        },
        "query": "query Profile($id: ID!) {\n  getProfile(id: $id) {\n    id\n    name\n    profileType\n    status\n    additionalSettings {\n      id\n      key\n      value\n      __typename\n    }\n    tags {\n      id\n      tag\n      __typename\n    }\n    latestEnforcedPolicy {\n      timestamp\n      version\n      __typename\n    }\n    objectStatus\n    numberOfAgents\n    numberOfOutdatedAgents\n    usedBy {\n      id\n      name\n      subType\n      __typename\n    }\n    ... on KubernetesProfile {\n      profileSubType\n      maxNumberOfAgents\n      authentication {\n        authenticationType\n        tokens {\n          token\n          id\n          expirationTime\n          __typename\n        }\n        __typename\n      }\n      upgradeMode\n      upgradeTime {\n        duration\n        time\n        scheduleType\n        ... on ScheduleDaysInMonth {\n          days\n          __typename\n        }\n        ... on ScheduleDaysInWeek {\n          weekDays\n          __typename\n        }\n        __typename\n      }\n      onlyDefinedApplications\n      failOpenInspection\n      managerInfo {\n        managerId\n        managerName\n        __typename\n      }\n      profileManagedBy\n      __typename\n    }\n    ... on VirtualNSaaSProfile {\n      cloudVendor\n      cloudAccounts {\n        id\n        accountId\n        accountRegions {\n          id\n          regionName\n          vpcEndpointService\n          __typename\n        }\n        __typename\n      }\n      managerInfo {\n        managerId\n        managerName\n        __typename\n      }\n      ARNOutboundCertificate\n      __typename\n    }\n    ... on AppSecSaaSProfile {\n      region\n      maxNumberOfAgents\n      failOpenInspection\n      certificateDomains {\n        id\n        domain\n        certificateParameter {\n          id\n          ... on CertificateParameter {\n            isCPManaged\n            certificateFile {\n              id\n              name\n              __typename\n            }\n            keyName\n            certificateFileName\n            certificateExpirationDate\n            certificateARN\n            certificateARNForCloudfront\n            __typename\n          }\n          __typename\n        }\n        cnameName\n        cnameValue\n        certificateValidationStatus\n        validationInfo\n        __typename\n      }\n      usedByType {\n        assets {\n          id\n          name\n          ... on WebApplicationAsset {\n            URLs {\n              id\n              URL\n              __typename\n            }\n            upstreamURL\n            __typename\n          }\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    ... on EmbeddedProfile {\n      profileSubType\n      maxNumberOfAgents\n      authentication {\n        authenticationType\n        tokens {\n          token\n          id\n          expirationTime\n          __typename\n        }\n        __typename\n      }\n      upgradeMode\n      upgradeTime {\n        duration\n        time\n        scheduleType\n        ... on ScheduleDaysInMonth {\n          days\n          __typename\n        }\n        ... on ScheduleDaysInWeek {\n          weekDays\n          __typename\n        }\n        __typename\n      }\n      failOpenInspection\n      onlyDefinedApplications\n      profileManagedBy\n      managedByNginx\n      __typename\n    }\n    ... on QuantumProfile {\n      cloudId\n      maxNumberOfAgents\n      numberOfAgents\n      authentication {\n        authenticationType\n        tokens {\n          token\n          id\n          expirationTime\n          __typename\n        }\n        __typename\n      }\n      upgradeMode\n      upgradeTime {\n        duration\n        time\n        scheduleType\n        ... on ScheduleDaysInMonth {\n          days\n          __typename\n        }\n        ... on ScheduleDaysInWeek {\n          weekDays\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    ... on DockerProfile {\n      profileSubType\n      maxNumberOfAgents\n      vendor\n      isSelfManaged\n      authentication {\n        authenticationType\n        tokens {\n          token\n          id\n          expirationTime\n          __typename\n        }\n        __typename\n      }\n      upgradeMode\n      upgradeTime {\n        duration\n        time\n        scheduleType\n        ... on ScheduleDaysInMonth {\n          days\n          __typename\n        }\n        ... on ScheduleDaysInWeek {\n          weekDays\n          __typename\n        }\n        __typename\n      }\n      onlyDefinedApplications\n      failOpenInspection\n      managerInfo {\n        managerId\n        managerName\n        __typename\n      }\n      profileManagedBy\n      managedByNginx\n      __typename\n    }\n    ... on CloudNativeProfile {\n      maxNumberOfAgents\n      authentication {\n        authenticationType\n        tokens {\n          token\n          id\n          expirationTime\n          __typename\n        }\n        __typename\n      }\n      upgradeMode\n      upgradeTime {\n        duration\n        time\n        scheduleType\n        ... on ScheduleDaysInMonth {\n          days\n          __typename\n        }\n        ... on ScheduleDaysInWeek {\n          weekDays\n          __typename\n        }\n        __typename\n      }\n      onlyDefinedApplications\n      __typename\n    }\n    ... on CloudGuardAppSecGatewayProfile {\n      profileSubType\n      certificateType\n      maxNumberOfAgents\n      authentication {\n        authenticationType\n        tokens {\n          token\n          id\n          expirationTime\n          __typename\n        }\n        __typename\n      }\n      upgradeMode\n      upgradeTime {\n        duration\n        time\n        scheduleType\n        ... on ScheduleDaysInMonth {\n          days\n          __typename\n        }\n        ... on ScheduleDaysInWeek {\n          weekDays\n          __typename\n        }\n        __typename\n      }\n      usedByType {\n        assets {\n          id\n          name\n          assetType\n          class\n          category\n          family\n          group\n          order\n          kind\n          tags {\n            id\n            tag\n            __typename\n          }\n          ... on WebApplicationAsset {\n            URLs {\n              id\n              URL\n              __typename\n            }\n            upstreamURL\n            __typename\n          }\n          __typename\n        }\n        __typename\n      }\n      reverseProxyUpstreamTimeout\n      reverseProxyAdditionalSettings {\n        key\n        value\n        __typename\n      }\n      failOpenInspection\n      __typename\n    }\n    ... on IotEnforcementProfile {\n      policyPackagesWithIotLayer {\n        id\n        name\n        type\n        subType\n        __typename\n      }\n      enforceIotLayerOnGateways {\n        id\n        name\n        type\n        subType\n        __typename\n      }\n      enforceIotLayerOnAllGateways\n      installPolicyOnEnforce\n      __typename\n    }\n    ... on IotConfigurationVirtualProfile {\n      iotState\n      shouldEnforceBetaRules\n      configurationsSettings {\n        id\n        key\n        value\n        __typename\n      }\n      __typename\n    }\n    ... on IotConfigurationProfile {\n      iotState\n      shouldEnforceBetaRules\n      configurationsSettings {\n        id\n        key\n        value\n        __typename\n      }\n      __typename\n    }\n    ... on IotBuiltinDiscoveryProfile {\n      numberOfLogicalAgents\n      additionalSettings {\n        id\n        key\n        value\n        __typename\n      }\n      integrationType\n      arguments\n      dnsProbing\n      mdnsProbing\n      upnpProbing\n      snmpProbing\n      sshProbing\n      httpProbing\n      telnetProbing\n      ftpProbing\n      matchQuery\n      installDiscoveryOnMgmt\n      installDiscoveryOnAllGateWays\n      installDiscoveryOn {\n        id\n        name\n        type\n        subType\n        __typename\n      }\n      enforceAssetsOnPolicyPackages {\n        id\n        name\n        type\n        subType\n        __typename\n      }\n      sendAssetsToGateways\n      __typename\n    }\n    ... on IotRiskProfile {\n      numberOfLogicalAgents\n      matchQuery\n      overrideSettings\n      configurationSettings\n      installDiscoveryOnMgmt\n      installDiscoveryOnAllGateWays\n      installDiscoveryOn {\n        id\n        name\n        type\n        subType\n        __typename\n      }\n      runActiveNmapProbing\n      __typename\n    }\n    ... on SdWanProfile {\n      matchQuery\n      SdWanGateways {\n        id\n        name\n        objectStatus\n        __typename\n      }\n      numberOfAgents\n      __typename\n    }\n    ... on IoTEmbeddedProfile {\n      maxNumberOfAgents\n      authentication {\n        authenticationType\n        tokens {\n          token\n          id\n          expirationTime\n          __typename\n        }\n        __typename\n      }\n      upgradeMode\n      upgradeTime {\n        duration\n        time\n        scheduleType\n        ... on ScheduleDaysInMonth {\n          days\n          __typename\n        }\n        ... on ScheduleDaysInWeek {\n          weekDays\n          __typename\n        }\n        __typename\n      }\n      failOpenInspection\n      onlyDefinedApplications\n      profileManagedBy\n      __typename\n    }\n    __typename\n  }\n}\n",
    };
    const response = await fetch(url, {
        method: "POST",
        headers: headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        console.log("Profile fetched successfully");
        const data = await response.json();
        //console.log("data:", data);
        return data?.data?.getProfile;
    } else {
        console.error("Failed to fetch profile");
        const errorData = await response.json();
        console.error("Error data:", errorData);
    }
    return null
}

//updaate certificate
async function updateCertificate(uri, certificateARNForCloudfront, certificateARN, certId, certPem) {
    const url = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql";
    const token = wafSession?.data?.token;
    const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
    };
    const certPemB64 = btoa(certPem);
    const body = {
        "operationName": "updateDomainCertificate",
        "variables": {
            "id": certId,
            "parameterInput": {
                "certificateARNForCloudfront": certificateARNForCloudfront,
                "certificateARN": certificateARN,
                "keyName": `${uri}-${Date.now()}.key.pem`,
                "certificateFile": `data:application/octet-stream;base64,${certPemB64}`,
                "certificateFileName": `${uri}-${Date.now()}.crt.pem`,
                "isCPManaged": false,
                "uri": uri
            },
        },
        "query": "mutation updateDomainCertificate($parameterInput: CertificateUpdateInput, $id: ID!) {\n  updateDomainCertificate(parameterInput: $parameterInput, id: $id)\n}\n"
    }
    const response = await fetch(url, {
        method: "POST",
        headers: headers,
        body: JSON.stringify(body),
    });
    if (response.ok) {
        console.log("Certificate updated successfully");
        const data = await response.json();
        // console.log("data:", data);
        return data?.data?.updateDomainCertificate;
    }
    else {
        console.error("Failed to update certificate");
        const errorData = await response.json();
        console.error("Error data:", errorData);
    }
    return null

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
    FILEPATH = `./${formattedDate}_upload-certificates_output.log`; // File path with the formatted date
        
    const config = await loadConfig("certificates.yaml");
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
     if (config?.urls) {
        // Loop through each asset in the configuration
        for (const asset of config.urls) {
            const assetDataInput = {
                ASSET_URL: asset.url,
                ASSET_DOMAIN: asset.domain,
                ASSET_CERT_PEM: asset.cert_pem,
                ASSET_CERT_KEY: asset.cert_key
            };     
            console.log("--------- URL ", assetDataInput.ASSET_URL ,"started ---------");
            const profile = await getProfile(PROFILE_PID)
            const certificateDomainList = profile.certificateDomains?.map((domainObj: any) => ({
                domain: domainObj.domain,
                id: domainObj.certificateParameter?.id,
            }));
            const updatedCertificateDomainList = certificateDomainList.map((item: any) => ({
                ...item,
                domain: `https://${item.domain}`, // Add "https://" to the beginning of the domain
            }));
            //console.log("Updated certificate domain list:", updatedCertificateDomainList);
            
            const certificateDomainParematerIdNAME = updatedCertificateDomainList.find((item: any) => item.domain === assetDataInput.ASSET_URL);
            const certificateDomainParematerId = certificateDomainParematerIdNAME?.id;
            console.log("certificateDomainParematerId:", certificateDomainParematerId);
               if (certificateDomainParematerId) {
                const publicKey = await getEncryptionPublicKey(PROFILE_PID, REGION)
                // console.log("Public key:", publicKey);
                 const keyFile = assetDataInput.ASSET_CERT_KEY
                 const key = await Deno.readTextFile(keyFile)
                 const certFile = assetDataInput.ASSET_CERT_PEM 
                 const cert = await Deno.readTextFile(certFile)
                 //console.log("key:", key);
                 //console.log("cert:", cert);
                 const result = await encryptPrivateKey(key, publicKey);
                 console.log("Encrypted public key and private key")
                 //console.log(result);
                 const addSensitiveFieldRes = await addSensitiveField(
                     PROFILE_PID,
                     REGION,
                     result.encryptedData,
                     result.encryptedKey,
                     cert
                 );
                   console.log("Uploading certificate for domain:", assetDataInput.ASSET_URL);
                   const certUpdate = await updateCertificate(
                   assetDataInput.ASSET_DOMAIN,
                   addSensitiveFieldRes?.certificateARNForCloudfront,
                   addSensitiveFieldRes?.certificateArn,
                   certificateDomainParematerId,
                   cert
                   )
                   await writeToFile(FILEPATH, `Certificate uploaded successfully ${assetDataInput.ASSET_URL} \n`);
                   await publishAndEnforce();
               }else{
                await writeToFile(FILEPATH, `Certificate uploaded failed ${assetDataInput.ASSET_URL} \n`);
                console.log("Failed to upload certificate for domain:", assetDataInput.ASSET_URL, "URL not found in the profile");
               }
              console.log("--------- URL ", assetDataInput.ASSET_URL ,"end ---------");
        }
    }
    return;
}


main()
    .then(() => {
        console.log("done");
    })
    .catch((error) => {
        console.error("Error:", error);
    });