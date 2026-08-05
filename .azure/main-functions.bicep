@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Container image to run, e.g. <acr>.azurecr.io/snyk-ghe:1.0.0. Defaults to a placeholder until you push the real image.')
param containerImage string = 'mcr.microsoft.com/k8se/quickstart:latest'

@description('Object id (principal id) of the user/service principal running this deployment. Granted Key Vault Secrets Officer so the template can write secret values.')
param deployerObjectId string

@description('Principal type of deployerObjectId. A pipeline/service-principal deployment uses ServicePrincipal (the default); set User when a person runs the deployment. Setting it explicitly is required in subscriptions where role-assignment rights are granted through an ABAC condition that constrains the assignee principal type.')
@allowed(['User', 'Group', 'ServicePrincipal'])
param deployerPrincipalType string = 'ServicePrincipal'

// --- Application configuration (non-secret) ---
@description('ghe.com REST API base, e.g. https://api.SUBDOMAIN.ghe.com/')
param gitHubApiBaseUrl string

@description('Numeric GitHub App id.')
param gitHubAppId int

@description('Default Snyk org id for GitHub orgs without an explicit mapping.')
param snykDefaultOrgId string = ''

@description('Default gate severity: low | medium | high | critical.')
param snykDefaultSeverity string = 'high'

@description('Default manifest ecosystem.')
param snykDefaultEcosystem string = 'nuget'

@description('When true, also run `snyk monitor` so the PR check can deep-link to the scan in the Snyk Web UI. Creates a Snyk project per repository.')
param snykMonitor bool = false

@description('Timeout in seconds for a single `snyk monitor` invocation. Monitoring uploads a dependency snapshot and can outrun a test scan on large repos, so it has its own bound. On timeout the monitor is skipped and the check simply has no Snyk link.')
param snykMonitorTimeoutSeconds int = 900

@description('When true, run `snyk code test` (SAST) and publish a separate sast/snyk Check Run. Requires the Snyk Code product on the org.')
param snykScanCode bool = false

@description('When true, run `snyk iac test` and publish a separate iac/snyk Check Run. Repos with no IaC files skip the check.')
param snykScanIac bool = false

@description('When true, attach Snyk Code findings as PR Check Run annotations (inline on Files changed). No extra permission needed.')
param snykAnnotatePullRequests bool = true

@description('When true, best-effort upload the Snyk Code SARIF to GitHub code scanning (Security tab with source snippets). Needs code scanning / GHAS on the repo and the App security_events permission; skipped silently when absent.')
param snykUploadSarifToCodeScanning bool = true

// Each scanner picks its engine independently so a product can be moved to the Test API, or rolled back,
// without touching the others. IaC has no engine parameter: Snyk's Test API accepts an `iac` scan config
// but no resource type feeds it a scan component, so the app rejects Snyk:Engines:Iac=Api at startup.
@description('Engine for the Open Source (SCA) scan. Api submits dependency graphs to the Snyk Test API; Cli runs `snyk test`.')
@allowed(['Cli', 'Api'])
param snykEngineOpenSource string = 'Cli'

@description('Engine for the Code (SAST) scan. Api requires snykScmIntegrationId and repositories imported through that SCM integration.')
@allowed(['Cli', 'Api'])
param snykEngineCode string = 'Cli'

@description('Snyk SCM integration id (GET /v1/org/{orgId}/integrations). Required when snykEngineCode is Api: the API-backed Code scan reads source through the integration, so repositories imported by the CLI are not visible to it.')
param snykScmIntegrationId string = ''

// --- Secrets (written to Key Vault) ---
// The GitHub App private key and webhook secret are NOT deploy inputs: the manifest-registration flow
// (/api/github/app/register) generates them and writes them to Key Vault at runtime. The app reads them
// from Key Vault, so the template neither seeds nor overwrites them.
@secure()
@description('Snyk group-level service account token. Optional: supply this or the OAuth client-credentials pair (or both). At least one is required for scans to authenticate.')
param snykToken string = ''

@description('Snyk OAuth 2.0 client-credentials service account id (optional alternative/complement to snykToken). A public identifier, not a secret — passed as plain config, not stored in Key Vault.')
param snykOAuthClientId string = ''

@secure()
@description('Snyk OAuth 2.0 client-credentials service account secret. Paired with snykOAuthClientId.')
param snykOAuthClientSecret string = ''

@secure()
@description('API key protecting the admin mapping endpoint.')
param adminApiKey string

@description('Service Bus queue that buffers webhook deliveries between the Function and the scan worker.')
param serviceBusQueueName string = 'webhook-deliveries'

@description('Maximum number of scan-processor replicas. With one message processed per replica (see serviceBusMessageCount) this is the ceiling on concurrent scans. Scale to zero is preserved (min replicas stays 0).')
param maxReplicas int = 4

@description('KEDA azure-servicebus target: queued messages per replica. 1 gives one replica per queued message (up to maxReplicas), so with the default per-replica concurrency of 1 the effective concurrent-scan count equals the replica count.')
param serviceBusMessageCount int = 1

@description('Seconds a replica may take to drain an in-flight scan after SIGTERM (scale-in or a new revision) before the platform sends SIGKILL. Must exceed the host shutdown timeout so the in-process drain finishes first.')
param terminationGracePeriodSeconds int = 300

@description('Seconds the .NET host waits for the queue worker to drain in-flight scans on shutdown (maps to Host:ShutdownTimeoutSeconds). Keep below terminationGracePeriodSeconds so the drain completes before SIGKILL.')
param hostShutdownTimeoutSeconds int = 240

@description('dotnet-isolated runtime version for the Function. Must be a version Flex Consumption supports in your region.')
param functionRuntimeVersion string = '10.0'

// --- Resource names ---
// Names default to values derived from baseName, so a self-contained deployment needs only baseName.
// Override any individually to fit an existing naming convention.
@description('Base name used to derive default resource names. Lowercase letters and numbers.')
@minLength(3)
@maxLength(17)
param baseName string

@description('Storage account name. 3-24 chars, lowercase alphanumeric, globally unique.')
param storageName string = toLower('${baseName}stg')
@description('Key Vault name. 3-24 chars, globally unique.')
param kvName string = 'kv${baseName}'
@description('Service Bus namespace name. Globally unique.')
param sbName string = 'sbns-${baseName}'
@description('Application Insights component name.')
param aiName string = '${baseName}-ai'
@description('User-assigned managed identity name.')
param uamiName string = 'id-${baseName}-worker'
@description('Function App (webhook front door) name. Globally unique.')
param functionName string = '${baseName}-fn'
@description('Container App (scan processor) name.')
param appName string = '${baseName}-app'
@description('Flex Consumption plan name.')
param planName string = 'plan-${baseName}'

// --- Shared resources: create by default, or bring your own ---
// The registry, Container Apps environment, and Log Analytics workspace are each created by this template
// by default (self-contained deployment). To reuse an existing shared / VNet-integrated / centrally-governed
// resource instead, set the matching create* to false and point *Name (and *ResourceGroup for a resource in
// another group) at it — this template then references it rather than owning it.
@description('Create the Azure Container Registry (false references an existing one via acrName/acrResourceGroup).')
param createAcr bool = true
@description('Container Registry name.')
param acrName string = toLower('${baseName}acr')
@description('Resource group of the Container Registry. Defaults to this deployment resource group.')
param acrResourceGroup string = resourceGroup().name
@description('Role granted to the runtime identity for image pull. Default AcrPull suits RBAC-only registries; for an ABAC-enabled registry (roleAssignmentMode=AbacRepositoryPermissions, where AcrPull is not honored) use Container Registry Repository Reader b93aa761-3e63-49ed-ac28-beffa264f7ac.')
param acrPullRoleId string = '7f951dda-4ed3-4680-a7ca-43fe172d538d'

@description('Create the Container Apps environment (false references an existing one via envName/envResourceGroup).')
param createEnvironment bool = true
@description('Container Apps environment name.')
param envName string = toLower('cae-${baseName}-${location}')
@description('Resource group of the Container Apps environment. Defaults to this deployment resource group.')
param envResourceGroup string = resourceGroup().name
@description('Workload profile to run the app on. Empty for a Consumption-only environment; set (e.g. Consumption) for a workload-profiles environment.')
param workloadProfileName string = ''

@description('Create the Log Analytics workspace (false references an existing one via lawName/lawResourceGroup).')
param createLogAnalytics bool = true
@description('Log Analytics workspace name.')
param lawName string = 'log-${baseName}'
@description('Resource group of the Log Analytics workspace. Defaults to this deployment resource group.')
param lawResourceGroup string = resourceGroup().name

var deploymentContainerName = 'app-package'

// Built-in role definition ids
var roleStorageTableDataContributor = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3')
var roleStorageBlobDataOwner = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b')
var roleStorageQueueDataContributor = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '974c5e8b-45b9-4653-ba55-5f855dd0fb88')
var roleKeyVaultSecretsUser = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
var roleKeyVaultSecretsOfficer = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')
// Azure Service Bus Data Owner — the Function sends, the Container App receives, and the KEDA scaler
// reads queue depth; this one role covers all three for the shared identity.
var roleServiceBusDataOwner = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '090c5cfd-751d-490a-894a-3ce6f1109419')
var roleMonitoringMetricsPublisher = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3913510d-42f4-4e42-8a64-420c390055eb')

resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: uamiName
  location: location
}

resource lawCreate 'Microsoft.OperationalInsights/workspaces@2023-09-01' = if (createLogAnalytics) {
  name: lawName
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource lawExisting 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = if (!createLogAnalytics) {
  name: lawName
  scope: resourceGroup(lawResourceGroup)
}

var lawId = createLogAnalytics ? lawCreate.id : lawExisting.id

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: aiName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: lawId
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
  }

  resource tableService 'tableServices@2023-05-01' = {
    name: 'default'

    resource table 'tables@2023-05-01' = {
      name: 'installations'
    }
  }

  resource blobService 'blobServices@2023-05-01' = {
    name: 'default'

    // Flex Consumption pulls the app's deployment package from this blob container using the identity.
    resource deploymentContainer 'containers@2023-05-01' = {
      name: deploymentContainerName
    }
  }
}

resource serviceBus 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' = {
  name: sbName
  location: location
  sku: { name: 'Standard', tier: 'Standard' }
  properties: {
    minimumTlsVersion: '1.2'
    disableLocalAuth: true
  }

  resource queue 'queues@2022-10-01-preview' = {
    name: serviceBusQueueName
    properties: {
      // A poisoned delivery is retried then dead-lettered instead of blocking the queue or being lost.
      maxDeliveryCount: 5
      deadLetteringOnMessageExpiration: true
      lockDuration: 'PT5M'
      defaultMessageTimeToLive: 'P1D'
    }
  }
}

resource acrCreate 'Microsoft.ContainerRegistry/registries@2023-07-01' = if (createAcr) {
  name: acrName
  location: location
  sku: { name: 'Standard' }
  properties: {
    adminUserEnabled: false
  }
}

resource acrExisting 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = if (!createAcr) {
  name: acrName
  scope: resourceGroup(acrResourceGroup)
}

// The create flag selects which of the two resources is actually deployed, so the ternary only reads the
// non-null one; the analyzer cannot prove that, hence the suppression.
#disable-next-line BCP318
var acrServer = createAcr ? acrCreate.properties.loginServer : acrExisting.properties.loginServer

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: kvName
  location: location
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: tenant().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
  }
}

// github-app-private-key and github-webhook-secret are intentionally absent: registration writes them to
// Key Vault at runtime. The Container App loads the private key via the Key Vault configuration provider,
// and the Function reads the webhook secret via an App Service Key Vault reference (which tolerates the
// secret being absent until registration runs).

// Snyk auth secrets are created only for the values supplied — Key Vault rejects empty secret values, and
// the app authenticates with whichever of token / OAuth client-credentials is present.
resource secretSnykToken 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (!empty(snykToken)) {
  parent: kv
  name: 'snyk-token'
  properties: { value: snykToken }
  dependsOn: [ deployerSecretsOfficer ]
}

resource secretSnykOAuthClientSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (!empty(snykOAuthClientSecret)) {
  parent: kv
  name: 'snyk-oauth-client-secret'
  properties: { value: snykOAuthClientSecret }
  dependsOn: [ deployerSecretsOfficer ]
}

resource secretAdminKey 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: kv
  name: 'admin-api-key'
  properties: { value: adminApiKey }
  dependsOn: [ deployerSecretsOfficer ]
}

// --- RBAC ---
resource tableDataContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, uami.id, roleStorageTableDataContributor)
  scope: storage
  properties: {
    roleDefinitionId: roleStorageTableDataContributor
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// The Flex Consumption host uses blobs (deployment package + leases) and queues (internal coordination)
// on the storage account via the managed identity.
resource blobDataOwner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, uami.id, roleStorageBlobDataOwner)
  scope: storage
  properties: {
    roleDefinitionId: roleStorageBlobDataOwner
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource queueDataContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, uami.id, roleStorageQueueDataContributor)
  scope: storage
  properties: {
    roleDefinitionId: roleStorageQueueDataContributor
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource secretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, uami.id, roleKeyVaultSecretsUser)
  scope: kv
  properties: {
    roleDefinitionId: roleKeyVaultSecretsUser
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource deployerSecretsOfficer 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, deployerObjectId, roleKeyVaultSecretsOfficer)
  scope: kv
  properties: {
    roleDefinitionId: roleKeyVaultSecretsOfficer
    principalId: deployerObjectId
    principalType: deployerPrincipalType
  }
}

// The self-service registration flow runs on the Container App and writes the generated App private key
// and webhook secret back to Key Vault, so the runtime identity needs write (Secrets Officer), not just
// the read (Secrets User) granted above.
resource uamiSecretsOfficer 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, uami.id, roleKeyVaultSecretsOfficer)
  scope: kv
  properties: {
    roleDefinitionId: roleKeyVaultSecretsOfficer
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Image-pull role for the runtime identity. The registry may live in another resource group (bring-your-
// own), and a role assignment can only be declared in the target resource's resource group, so it is always
// deployed through a module scoped to the registry's group — which resolves to this group in the create
// case. The role id is parameterized because ABAC-enabled registries don't honor AcrPull (see acrPullRoleId).
module acrPull 'modules/acr-pull-role.bicep' = {
  name: 'deploy-acrpull'
  scope: resourceGroup(acrResourceGroup)
  params: {
    acrName: acrName
    principalId: uami.properties.principalId
    roleDefinitionId: acrPullRoleId
  }
  dependsOn: [ acrCreate ]
}

resource serviceBusDataOwner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(serviceBus.id, uami.id, roleServiceBusDataOwner)
  scope: serviceBus
  properties: {
    roleDefinitionId: roleServiceBusDataOwner
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource metricsPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(appInsights.id, uami.id, roleMonitoringMetricsPublisher)
  scope: appInsights
  properties: {
    roleDefinitionId: roleMonitoringMetricsPublisher
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// --- Function front door (Flex Consumption) ---
resource functionPlan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: planName
  location: location
  kind: 'functionapp'
  sku: { tier: 'FlexConsumption', name: 'FC1' }
  properties: {
    reserved: true
  }
}

resource functionApp 'Microsoft.Web/sites@2024-04-01' = {
  name: functionName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${uami.id}': {}
    }
  }
  properties: {
    serverFarmId: functionPlan.id
    httpsOnly: true
    keyVaultReferenceIdentity: uami.id
    siteConfig: {
      minTlsVersion: '1.2'
    }
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storage.properties.primaryEndpoints.blob}${deploymentContainerName}'
          authentication: {
            type: 'UserAssignedIdentity'
            userAssignedIdentityResourceId: uami.id
          }
        }
      }
      scaleAndConcurrency: {
        maximumInstanceCount: 40
        instanceMemoryMB: 2048
      }
      runtime: {
        name: 'dotnet-isolated'
        version: functionRuntimeVersion
      }
    }
  }

  resource appsettings 'config@2024-04-01' = {
    name: 'appsettings'
    properties: {
      AzureWebJobsStorage__accountName: storage.name
      AzureWebJobsStorage__credential: 'managedidentity'
      AzureWebJobsStorage__clientId: uami.properties.clientId
      APPLICATIONINSIGHTS_CONNECTION_STRING: appInsights.properties.ConnectionString
      APPLICATIONINSIGHTS_AUTHENTICATION_STRING: 'ClientId=${uami.properties.clientId};Authorization=AAD'
      ServiceBusConnection__fullyQualifiedNamespace: '${serviceBus.name}.servicebus.windows.net'
      ServiceBusConnection__credential: 'managedidentity'
      ServiceBusConnection__clientId: uami.properties.clientId
      ServiceBusQueueName: serviceBusQueueName
      GitHubWebhookSecret: '@Microsoft.KeyVault(SecretUri=${kv.properties.vaultUri}secrets/github-webhook-secret)'
    }
  }
  dependsOn: [
    blobDataOwner
    queueDataContributor
    secretsUser
    serviceBusDataOwner
  ]
}

// --- Processing tier (Container App, scales to zero) ---
resource envCreate 'Microsoft.App/managedEnvironments@2024-03-01' = if (createEnvironment) {
  name: envName
  location: location
  properties: {
    // Send logs to Azure Monitor; the diagnostic setting below routes them to the Log Analytics workspace.
    // Logs land in the dedicated ContainerAppConsoleLogs / ContainerAppSystemLogs tables (no _CL suffix,
    // Log column not Log_s) — query those, not the _CL custom-log tables.
    appLogsConfiguration: {
      destination: 'azure-monitor'
    }
  }
}

resource envExisting 'Microsoft.App/managedEnvironments@2024-03-01' existing = if (!createEnvironment) {
  name: envName
  scope: resourceGroup(envResourceGroup)
}

var envId = createEnvironment ? envCreate.id : envExisting.id
// See acrServer above: the create flag guarantees only the deployed branch is read.
#disable-next-line BCP318
var envDefaultDomain = createEnvironment ? envCreate.properties.defaultDomain : envExisting.properties.defaultDomain

// When this template creates the environment, route its console logs to the workspace. A bring-your-own
// environment is expected to carry its own diagnostics, so this is skipped in that case.
resource envDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (createEnvironment) {
  name: 'send-app-logs-to-log-analytics'
  scope: envCreate
  properties: {
    workspaceId: lawId
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      { category: 'ContainerAppConsoleLogs', enabled: true }
    ]
  }
}

// Wire only the Snyk auth values that were supplied (Container App secretRefs must resolve to a secret that
// actually exists). The app reads SNYK_TOKEN and/or the OAuth client-credentials pair, whichever is present.
var snykAuthAppSecrets = concat(
  empty(snykToken) ? [] : [ { name: 'snyk-token', keyVaultUrl: '${kv.properties.vaultUri}secrets/snyk-token', identity: uami.id } ],
  empty(snykOAuthClientSecret) ? [] : [ { name: 'snyk-oauth-client-secret', keyVaultUrl: '${kv.properties.vaultUri}secrets/snyk-oauth-client-secret', identity: uami.id } ]
)
var snykAuthEnv = concat(
  empty(snykToken) ? [] : [ { name: 'Snyk__Token', secretRef: 'snyk-token' } ],
  empty(snykOAuthClientId) ? [] : [ { name: 'Snyk__OAuthClientId', value: snykOAuthClientId } ],
  empty(snykOAuthClientSecret) ? [] : [ { name: 'Snyk__OAuthClientSecret', secretRef: 'snyk-oauth-client-secret' } ]
)

resource app 'Microsoft.App/containerApps@2025-07-01' = {
  name: appName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${uami.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: envId
    // Absent for a Consumption-only environment; set to a profile name for a workload-profiles environment.
    workloadProfileName: empty(workloadProfileName) ? null : workloadProfileName
    configuration: {
      // Ingress serves only the admin/registration routes (e.g. /api/github/app/register). GitHub webhooks
      // still flow through the Function front door, so this endpoint sees no GitHub-timeout-bound traffic; a
      // cold-start wake on an occasional admin call is acceptable. The app still scales to zero, and queue
      // messages wake it via the KEDA Service Bus rule below.
      ingress: {
        external: true
        targetPort: 8080
        transport: 'auto'
        allowInsecure: false
      }
      registries: [
        {
          server: acrServer
          identity: uami.id
        }
      ]
      secrets: concat([
        {
          name: 'admin-api-key'
          keyVaultUrl: '${kv.properties.vaultUri}secrets/admin-api-key'
          identity: uami.id
        }
      ], snykAuthAppSecrets)
    }
    template: {
      // Give an in-flight scan time to finish before SIGKILL when a replica is scaled in or the
      // revision is replaced. The host's ShutdownTimeout (Program.cs) drains the Service Bus
      // processor within this window; it must stay below this value so the drain completes first.
      terminationGracePeriodSeconds: terminationGracePeriodSeconds
      containers: [
        {
          name: 'webhookservice'
          image: containerImage
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: concat([
            // DefaultAzureCredential selects this user-assigned identity for Storage, Key Vault, and Service Bus.
            { name: 'AZURE_CLIENT_ID', value: uami.properties.clientId }
            // Application Insights for the processing tier: the ASP.NET host reads the connection string to
            // emit traces, and authenticates ingestion through the managed identity (granted Monitoring
            // Metrics Publisher below) rather than an instrumentation key.
            { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appInsights.properties.ConnectionString }
            { name: 'APPLICATIONINSIGHTS_AUTHENTICATION_STRING', value: 'ClientId=${uami.properties.clientId};Authorization=AAD' }
            // A Container App sets no WEBSITE_SITE_NAME, so App Insights would leave cloud_RoleName empty;
            // name this tier explicitly so it is distinguishable from the Function in the Application Map.
            { name: 'APPLICATIONINSIGHTS_ROLE_NAME', value: appName }
            { name: 'GitHub__ApiBaseUrl', value: gitHubApiBaseUrl }
            { name: 'GitHub__AppId', value: string(gitHubAppId) }
            // GitHub__PrivateKeyPem is loaded from Key Vault at runtime via the app's Key Vault
            // configuration provider, not injected here — registration writes it after deploy.
            { name: 'Snyk__DefaultSnykOrgId', value: snykDefaultOrgId }
            { name: 'Snyk__DefaultSeverityThreshold', value: snykDefaultSeverity }
            { name: 'Snyk__DefaultEcosystem', value: snykDefaultEcosystem }
            { name: 'Snyk__Monitor', value: string(snykMonitor) }
            { name: 'Snyk__MonitorTimeoutSeconds', value: string(snykMonitorTimeoutSeconds) }
            { name: 'Snyk__ScanCode', value: string(snykScanCode) }
            { name: 'Snyk__ScanIac', value: string(snykScanIac) }
            { name: 'Snyk__AnnotatePullRequests', value: string(snykAnnotatePullRequests) }
            { name: 'Snyk__UploadSarifToCodeScanning', value: string(snykUploadSarifToCodeScanning) }
            { name: 'Snyk__Engines__OpenSource', value: snykEngineOpenSource }
            { name: 'Snyk__Engines__Code', value: snykEngineCode }
            { name: 'Snyk__ScmIntegrationId', value: snykScmIntegrationId }
            { name: 'Storage__TableServiceUri', value: storage.properties.primaryEndpoints.table }
            { name: 'Storage__TableName', value: 'installations' }
            { name: 'Storage__AdminApiKey', secretRef: 'admin-api-key' }
            { name: 'ServiceBus__FullyQualifiedNamespace', value: '${serviceBus.name}.servicebus.windows.net' }
            { name: 'ServiceBus__QueueName', value: serviceBusQueueName }
            { name: 'Host__ShutdownTimeoutSeconds', value: string(hostShutdownTimeoutSeconds) }
            // Registration runs here, but the manifest's webhook URL must point at the Function front door,
            // not this container — otherwise GitHub would deliver webhooks straight to the scale-to-zero app.
            { name: 'Registration__PublicBaseUrl', value: 'https://${appName}.${envDefaultDomain}' }
            { name: 'Registration__WebhookUrl', value: 'https://${functionApp.properties.defaultHostName}/api/github/webhooks' }
            // Registration persists the generated private key + webhook secret to Key Vault. This app then
            // loads the private key from there via the Key Vault configuration provider; the Function reads
            // the webhook secret via its own Key Vault reference.
            { name: 'SecretRepository__Provider', value: 'AzureKeyVault' }
            { name: 'SecretRepository__KeyVaultUri', value: kv.properties.vaultUri }
          ], snykAuthEnv)
        }
      ]
      scale: {
        // Scale to zero when idle; wake on whichever fires first. The queue rule handles the webhook path;
        // the HTTP rule is required so an admin/registration call to the ingress can wake the app from zero.
        // A custom rule replaces the default HTTP scaler, so without an explicit http rule the ingress would
        // have nothing to activate the app and admin requests would hang.
        //
        // Concurrency: KEDA targets serviceBusMessageCount queued messages per replica, so a value of 1 gives
        // one replica per queued message up to maxReplicas. Each replica processes one message at a time
        // (ServiceBus:MaxConcurrentCalls defaults to 1), so maxReplicas is the concurrent-scan ceiling.
        minReplicas: 0
        maxReplicas: maxReplicas
        rules: [
          {
            name: 'servicebus-queue'
            custom: {
              type: 'azure-servicebus'
              metadata: {
                namespace: serviceBus.name
                queueName: serviceBusQueueName
                messageCount: string(serviceBusMessageCount)
              }
              identity: uami.id
            }
          }
          {
            name: 'http-admin'
            http: {
              metadata: {
                concurrentRequests: '10'
              }
            }
          }
        ]
      }
    }
  }
  dependsOn: [
    secretsUser
    uamiSecretsOfficer
    acrPull
    serviceBusDataOwner
    secretSnykToken
    secretSnykOAuthClientSecret
    secretAdminKey
  ]
}

output webhookUrl string = 'https://${functionApp.properties.defaultHostName}/api/github/webhooks'
output registrationUrl string = 'https://${app.properties.configuration.ingress.fqdn}/api/github/app/register'
output functionAppName string = functionApp.name
output acrLoginServer string = acrServer
output keyVaultName string = kv.name
output managedIdentityClientId string = uami.properties.clientId
output serviceBusNamespace string = '${serviceBus.name}.servicebus.windows.net'
