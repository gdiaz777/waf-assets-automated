// ============================================================================
// enforce-checkpoint-wafsaas.ts
// ----------------------------------------------------------------------------
// Standalone helper that logs in to the Infinity Portal, waits for any
// published-but-not-yet-enforced session to be ready, and triggers an
// enforcePolicy. Useful when a previous deploy/upload run finished without
// applying changes (e.g. the portal shows "Certificate issued. Enforce
// policy to proceed.").
//
// Usage:
//   dotenvx run -- deno run -A enforce-checkpoint-wafsaas.ts
// ============================================================================

const WAF_GRAPHQL_URL = "https://cloudinfra-gw.portal.checkpoint.com/app/waf//graphql";

let wafSession: any = null;

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

async function asyncPublishChanges() {
    const token = wafSession?.data?.token;
    const headers = { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" };
    const body = {
        operationName: "asyncPublishChanges",
        variables: { profileTypes: ["Docker", "CloudGuardAppSecGateway", "Embedded", "Kubernetes", "AppSecSaaS"] },
        query: "mutation asyncPublishChanges($profileTypes: [ProfileType!], $skipNginxValidation: Boolean) {\n  asyncPublishChanges(\n    profileTypes: $profileTypes\n    skipNginxValidation: $skipNginxValidation\n  )\n}\n",
    };
    const r = await fetch(WAF_GRAPHQL_URL, { method: "POST", headers, body: JSON.stringify(body) });
    if (r.ok) {
        const data = await r.json();
        return data?.data?.asyncPublishChanges;
    }
    console.error("asyncPublishChanges failed:", await r.json());
    return null;
}

async function enforcePolicy() {
    const token = wafSession?.data?.token;
    const headers = { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" };
    const body = {
        operationName: "enforcePolicy",
        variables: { profileTypes: ["Docker", "CloudGuardAppSecGateway", "Embedded", "Kubernetes", "AppSecSaaS"] },
        query: "mutation enforcePolicy($profilesIds: [ID!], $profileTypes: [ProfileType!]) {\n  enforcePolicy(profilesIds: $profilesIds, profileTypes: $profileTypes) {\n    id\n    tenantId\n    type\n    status\n    startTime\n    endTime\n    message\n    errorCode\n    referenceId\n    __typename\n  }\n}\n",
    };
    const r = await fetch(WAF_GRAPHQL_URL, { method: "POST", headers, body: JSON.stringify(body) });
    if (r.ok) {
        const data = await r.json();
        return data?.data?.enforcePolicy;
    }
    console.error("enforcePolicy failed:", await r.json());
    return null;
}

async function getTask(taskid: string) {
    const token = wafSession?.data?.token;
    const headers = { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" };
    const body = {
        variables: { id: taskid },
        query: "query getTask($id: ID!) {\n  getTask(id: $id) {\n    id\n    status\n    startTime\n  endTime\n   message\n    errorCode\n    referenceId\n    tenantId\n  }\n}\n",
    };
    const r = await fetch(WAF_GRAPHQL_URL, { method: "POST", headers, body: JSON.stringify(body) });
    if (r.ok) {
        const data = await r.json();
        return data?.data?.getTask;
    }
    return null;
}

async function waitForTask(taskId: string) {
    console.log("Waiting for taskId:", taskId);
    while (true) {
        const task = await getTask(taskId);
        const status = task?.status;
        console.log("Task status:", status);
        if (status !== "InProgress") break;
        await new Promise((r) => setTimeout(r, 2000));
    }
}

async function getUnenforcedPublishedSessions(): Promise<any[]> {
    const token = wafSession?.data?.token;
    const headers = { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" };
    const body = {
        operationName: "getUnenforcedPublishedSessions",
        variables: {},
        query: "query getUnenforcedPublishedSessions {\n  getUnenforcedPublishedSessions {\n    id\n    __typename\n  }\n}\n",
    };
    const r = await fetch(WAF_GRAPHQL_URL, { method: "POST", headers, body: JSON.stringify(body) });
    if (r.ok) {
        const data = await r.json();
        return data?.data?.getUnenforcedPublishedSessions ?? [];
    }
    return [];
}

async function waitForPublishedSession(maxAttempts = 30, intervalMs = 2000): Promise<boolean> {
    for (let i = 0; i < maxAttempts; i++) {
        const sessions = await getUnenforcedPublishedSessions();
        if (sessions.length > 0) {
            console.log(`Published session ready after ${i * intervalMs / 1000}s (${sessions.length} pending)`);
            return true;
        }
        await new Promise((r) => setTimeout(r, intervalMs));
    }
    return false;
}

async function main() {
    const url = Deno.env.get("WAFAUTHURL")!;
    const clientId = Deno.env.get("WAFKEY")!;
    const accessKey = Deno.env.get("WAFSECRET")!;

    wafSession = await wafLogin(url, clientId, accessKey);
    if (!wafSession) {
        console.error("Failed to login to WAF");
        return;
    }

    // 1. Trigger a publish so any pending tenant draft is surfaced.
    console.log("Publishing any pending changes...");
    const publish = await asyncPublishChanges();
    console.log("Publish result:", publish);

    // 2. Best-effort wait for the publish to settle. Do NOT gate on this —
    //    certificate/asset changes can need enforcement without showing
    //    up in getUnenforcedPublishedSessions.
    await waitForPublishedSession();

    // 3. Always run enforce. Worst case it is a no-op for an idle tenant.
    console.log("Enforcing policy...");
    const enforce = await enforcePolicy();
    console.log("Enforce result:", enforce);
    if (enforce?.id) await waitForTask(enforce.id);
    console.log("Done.");
}

main()
    .then(() => console.log("done"))
    .catch((error) => console.error("Error:", error));
