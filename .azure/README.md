# Infrastructure (Bicep)

Two deployment topologies are provided. Both run the **same** `SnykGhe.Service` container image
and share the same durable design — a Service Bus queue between webhook ingestion and the (slow) Snyk
scan — so installation registry, scanning, and fix-PR behaviour are identical. They differ only in who
the public webhook endpoint is and whether the processing tier is always on.

| | `main.bicep` — always-on | `main-functions.bicep` — scale-to-zero |
| --- | --- | --- |
| Public endpoint | Container App (external ingress) | Azure Function (Flex Consumption) |
| Queue | Azure Service Bus | Azure Service Bus |
| Processing tier | Container App, **always on** (min 1 replica) | Container App, **scales to zero** (KEDA Service Bus rule) |
| Idle cost | one warm replica | ~nothing when idle (Function per-execution + Service Bus) |
| Cold start | none | hidden behind the queue — GitHub is ACKed by the always-cheap Function |
| Extra moving parts | Service Bus | Service Bus, Function app, Flex plan, App Insights |

Pick always-on for the simplest always-warm service; pick scale-to-zero to minimise idle cost
(bursty / low-volume traffic) at the cost of a few more resources.

## Shared resources

| Resource | Purpose |
| --- | --- |
| User-assigned managed identity | App identity for Storage, Key Vault, ACR, and Service Bus — no connection strings |
| Log Analytics workspace | Diagnostics (and the App Insights workspace in the scale-to-zero topology) |
| Storage account + `installations` table | Installation registry |
| Service Bus namespace + queue | Durable buffer between webhook ingestion and scanning (retry + dead-letter) |
| Key Vault (RBAC) + secrets | GitHub App private key, webhook secret, Snyk token, admin key |
| Container Registry (ACR) | Hosts the service image |
| Container Apps environment + app | Runs the scan worker (and, in the always-on topology, receives webhooks) |

The managed identity is granted **Storage Table Data Contributor**, **Key Vault Secrets User**,
**AcrPull**, and **Azure Service Bus Data Owner** (send + receive + the queue-depth read the KEDA scaler
needs). The scale-to-zero topology additionally grants the identity **Storage Blob Data Owner** (Function
host storage + deployment container) and **Monitoring Metrics Publisher** (App Insights). The deploying
principal is granted **Key Vault Secrets Officer** so the template can write the secret values.

## Deploy — always-on (`main.bicep`)

```bash
# 1. Resource group
az group create -n rg-snyk-ghe -l eastus

# 2. Build & push the image (after first creating the ACR via a placeholder deploy, or use any registry)
az acr build -r <acrName> -t snyk-ghe:1.0.0 .

# 3. Deploy (secrets passed inline; PEM read from file)
az deployment group create \
  -g rg-snyk-ghe \
  -f .azure/main.bicep \
  -p .azure/main.sample.bicepparam \
  -p deployerObjectId=$(az ad signed-in-user show --query id -o tsv) \
     containerImage=<acrName>.azurecr.io/snyk-ghe:1.0.0 \
     gitHubPrivateKeyPem=@app-private-key.pem \
     gitHubWebhookSecret=<secret> \
     snykToken=<token> \
     adminApiKey=<key>
```

The deployment outputs `webhookUrl` — configure that as the GitHub App's webhook URL.

## Deploy — scale-to-zero (`main-functions.bicep`)

Same as above but with `-f .azure/main-functions.bicep -p .azure/main-functions.sample.bicepparam`.
Then publish the Function code (the template provisions the Function app but not its code):

```bash
# After the deployment, publish the forwarder Function (uses the functionAppName output)
cd src/SnykGhe.Functions
func azure functionapp publish <functionAppName> --dotnet-isolated
```

The `webhookUrl` output points at the Function (`https://<app>.azurewebsites.net/api/github/webhooks`).
The Container App has no ingress; it wakes from zero when messages land on the Service Bus queue.

## Local development

With no `ServiceBus:FullyQualifiedNamespace` configured, the service falls back to an in-process channel
queue — no Service Bus needed to run locally. This queue is **not durable** (queued work is lost on
restart), so it is for local/dev only; both deployment topologies always configure Service Bus.

## Notes

- **Key Vault RBAC propagation:** on a brand-new vault the deployer's Secrets Officer role can take a
  minute to propagate; if the first run fails writing secrets, re-run the same deployment (it is idempotent).
- **Secret rotation:** secrets are referenced from Key Vault versionlessly, so `az keyvault secret set`
  is picked up on the next revision restart (Container App) / app restart (Function) — no redeploy needed.
- **First image:** `containerImage` defaults to a public placeholder so the environment can stand up
  before your image exists. Push the real image and redeploy with the ACR tag.
- **Function runtime version:** `main-functions.bicep` defaults the Function to `dotnet-isolated` `10.0`.
  If a region or the Flex Consumption plan does not yet offer 10.0, override `functionRuntimeVersion`
  with a supported LTS (e.g. `8.0`).
- **Message size:** the queue carries the raw webhook body. The App subscribes only to `pull_request`
  and `installation` events, whose payloads sit well under the Service Bus 256 KB message limit.
```
