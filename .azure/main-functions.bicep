@description('Base name used to derive resource names. Lowercase letters and numbers.')
@minLength(3)
@maxLength(17)
param baseName string

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Container image to run, e.g. <acr>.azurecr.io/snyk-ghe:1.0.0. Defaults to a placeholder until you push the real image.')
param containerImage string = 'mcr.microsoft.com/k8se/quickstart:latest'

@description('Object id (principal id) of the user/service principal running this deployment. Granted Key Vault Secrets Officer so the template can write secret values.')
param deployerObjectId string

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

// --- Secrets (written to Key Vault) ---
@secure()
@description('PEM-encoded GitHub App private key.')
param gitHubPrivateKeyPem string

@secure()
@description('GitHub App webhook secret.')
param gitHubWebhookSecret string

@secure()
@description('Snyk group-level service account token.')
param snykToken string

@secure()
@description('API key protecting the admin mapping endpoint.')
param adminApiKey string

@description('Service Bus queue that buffers webhook deliveries between the Function and the scan worker.')
param serviceBusQueueName string = 'webhook-deliveries'

@description('dotnet-isolated runtime version for the Function. Must be a version Flex Consumption supports in your region.')
param functionRuntimeVersion string = '10.0'

var storageName = toLower('${baseName}stg')
var acrName = toLower('${baseName}acr')
var kvName = '${baseName}-kv'
var uamiName = '${baseName}-id'
var lawName = '${baseName}-law'
var envName = '${baseName}-cae'
var appName = '${baseName}-app'
var sbName = toLower('${baseName}-sb')
var planName = '${baseName}-fcplan'
var functionName = '${baseName}-fn'
var aiName = '${baseName}-ai'
var deploymentContainerName = 'app-package'

// Built-in role definition ids
var roleStorageTableDataContributor = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3')
var roleStorageBlobDataOwner = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b')
var roleStorageQueueDataContributor = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '974c5e8b-45b9-4653-ba55-5f855dd0fb88')
var roleKeyVaultSecretsUser = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
var roleKeyVaultSecretsOfficer = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')
var roleAcrPull = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
// Azure Service Bus Data Owner — the Function sends, the Container App receives, and the KEDA scaler
// reads queue depth; this one role covers all three for the shared identity.
var roleServiceBusDataOwner = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '090c5cfd-751d-490a-894a-3ce6f1109419')
var roleMonitoringMetricsPublisher = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3913510d-42f4-4751-9f13-9ccb3af68d1f')

resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: uamiName
  location: location
}

resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: lawName
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: aiName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: law.id
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

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: acrName
  location: location
  sku: { name: 'Standard' }
  properties: {
    adminUserEnabled: false
  }
}

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

resource secretPrivateKey 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: kv
  name: 'github-app-private-key'
  properties: { value: gitHubPrivateKeyPem }
  dependsOn: [ deployerSecretsOfficer ]
}

resource secretWebhook 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: kv
  name: 'github-webhook-secret'
  properties: { value: gitHubWebhookSecret }
  dependsOn: [ deployerSecretsOfficer ]
}

resource secretSnykToken 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: kv
  name: 'snyk-token'
  properties: { value: snykToken }
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
  }
}

resource acrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, uami.id, roleAcrPull)
  scope: acr
  properties: {
    roleDefinitionId: roleAcrPull
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
  }
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
    secretWebhook
  ]
}

// --- Processing tier (Container App, scales to zero) ---
resource env 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: envName
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: law.properties.customerId
        sharedKey: law.listKeys().primarySharedKey
      }
    }
  }
}

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
    managedEnvironmentId: env.id
    configuration: {
      // No ingress: the Function is the only public endpoint. The app wakes from zero on queue messages
      // via the KEDA Service Bus scale rule below.
      registries: [
        {
          server: acr.properties.loginServer
          identity: uami.id
        }
      ]
      secrets: [
        {
          name: 'github-private-key'
          keyVaultUrl: '${kv.properties.vaultUri}secrets/github-app-private-key'
          identity: uami.id
        }
        {
          name: 'snyk-token'
          keyVaultUrl: '${kv.properties.vaultUri}secrets/snyk-token'
          identity: uami.id
        }
        {
          name: 'admin-api-key'
          keyVaultUrl: '${kv.properties.vaultUri}secrets/admin-api-key'
          identity: uami.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'webhookservice'
          image: containerImage
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            // DefaultAzureCredential selects this user-assigned identity for Storage, Key Vault, and Service Bus.
            { name: 'AZURE_CLIENT_ID', value: uami.properties.clientId }
            { name: 'GitHub__ApiBaseUrl', value: gitHubApiBaseUrl }
            { name: 'GitHub__AppId', value: string(gitHubAppId) }
            { name: 'GitHub__PrivateKeyPem', secretRef: 'github-private-key' }
            { name: 'Snyk__Token', secretRef: 'snyk-token' }
            { name: 'Snyk__DefaultSnykOrgId', value: snykDefaultOrgId }
            { name: 'Snyk__DefaultSeverityThreshold', value: snykDefaultSeverity }
            { name: 'Snyk__DefaultEcosystem', value: snykDefaultEcosystem }
            { name: 'Storage__TableServiceUri', value: storage.properties.primaryEndpoints.table }
            { name: 'Storage__TableName', value: 'installations' }
            { name: 'Storage__AdminApiKey', secretRef: 'admin-api-key' }
            { name: 'ServiceBus__FullyQualifiedNamespace', value: '${serviceBus.name}.servicebus.windows.net' }
            { name: 'ServiceBus__QueueName', value: serviceBusQueueName }
          ]
        }
      ]
      scale: {
        // Scale to zero when idle; wake and scale out on queue depth. A scale rule is mandatory here
        // because ingress is disabled — without it the app could never start back up from zero.
        minReplicas: 0
        maxReplicas: 10
        rules: [
          {
            name: 'servicebus-queue'
            custom: {
              type: 'azure-servicebus'
              metadata: {
                namespace: serviceBus.name
                queueName: serviceBusQueueName
                messageCount: '5'
              }
              identity: uami.id
            }
          }
        ]
      }
    }
  }
  dependsOn: [
    secretsUser
    acrPull
    serviceBusDataOwner
    secretPrivateKey
    secretSnykToken
    secretAdminKey
  ]
}

output webhookUrl string = 'https://${functionApp.properties.defaultHostName}/api/github/webhooks'
output functionAppName string = functionApp.name
output acrLoginServer string = acr.properties.loginServer
output keyVaultName string = kv.name
output managedIdentityClientId string = uami.properties.clientId
output serviceBusNamespace string = '${serviceBus.name}.servicebus.windows.net'
