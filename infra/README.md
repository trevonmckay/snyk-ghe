# Infrastructure (Bicep)

`main.bicep` provisions the full Azure footprint for the service:

| Resource | Purpose |
| --- | --- |
| User-assigned managed identity | App identity for Storage, Key Vault, and ACR — no connection strings |
| Log Analytics workspace | Container Apps diagnostics |
| Storage account + `installations` table | Installation registry |
| Key Vault (RBAC) + secrets | GitHub App private key, webhook secret, Snyk token, admin key |
| Container Registry (ACR) | Hosts the service image |
| Container Apps environment + app | Runs the webhook service (external ingress, min 1 replica) |

The managed identity is granted **Storage Table Data Contributor**, **Key Vault Secrets User**, and **AcrPull**. The deploying principal is granted **Key Vault Secrets Officer** so the template can write the secret values.

## Deploy

```bash
# 1. Resource group
az group create -n rg-snyk-ghe -l eastus

# 2. Build & push the image (after first creating the ACR via a placeholder deploy, or use any registry)
az acr build -r <acrName> -t snyk-ghe:1.0.0 .

# 3. Deploy (secrets passed inline; PEM read from file)
az deployment group create \
  -g rg-snyk-ghe \
  -f infra/main.bicep \
  -p infra/main.sample.bicepparam \
  -p deployerObjectId=$(az ad signed-in-user show --query id -o tsv) \
     containerImage=<acrName>.azurecr.io/snyk-ghe:1.0.0 \
     gitHubPrivateKeyPem=@app-private-key.pem \
     gitHubWebhookSecret=<secret> \
     snykToken=<token> \
     adminApiKey=<key>
```

The deployment outputs `webhookUrl` — configure that as the GitHub App's webhook URL.

## Notes

- **Key Vault RBAC propagation:** on a brand-new vault the deployer's Secrets Officer role can take a minute to propagate; if the first run fails writing secrets, re-run the same deployment (it is idempotent).
- **Secret rotation:** the Container App uses versionless Key Vault references, so updating a secret with `az keyvault secret set` is picked up on the next revision restart — no redeploy needed.
- **First image:** `containerImage` defaults to a public placeholder so the environment can stand up before your image exists. Push the real image and redeploy with the ACR tag.
