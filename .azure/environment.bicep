// One-time platform/foundation deployment: the VNet-integrated Container Apps environment that hosts the
// scan-worker. Deployed ONCE, out of band — not from the app CI pipeline — because the environment and its
// networking are platform-owned and have a different lifecycle than the app's own resources. The app
// template (main-functions.bicep) then references this environment by name with createEnvironment=false and
// deploys the identity, data-plane resources, Function, and Container App on top of it.
//
// Prerequisites (also platform-owned, created out of band): the VNet and a subnet delegated to
// Microsoft.App/environments (minimum /27). Pass that subnet's resource id. Egress (a UDR routing
// 0.0.0.0/0 to a firewall or NAT) is configured on the subnet's route table OUTSIDE this template, after
// the environment exists — per Azure guidance, UDR is applied outside the environment scope.

@description('Azure region.')
param location string = resourceGroup().location

@description('Container Apps environment name.')
param envName string

@description('Resource id of the delegated infrastructure subnet (delegated to Microsoft.App/environments).')
param infrastructureSubnetId string

@description('Resource id of the Log Analytics workspace that receives the environment console logs.')
param logAnalyticsWorkspaceId string

@description('Internal-only environment (no public ingress load balancer). False exposes a public ingress IP; egress follows the subnet route table either way.')
param internalOnly bool = false

@description('Name of the built-in workload profile. Consumption keeps scale-to-zero.')
param workloadProfileName string = 'Consumption'

@description('Workload profile type. Consumption for scale-to-zero; a Dedicated type (e.g. D4) for reserved compute.')
param workloadProfileType string = 'Consumption'

resource env 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: envName
  location: location
  properties: {
    // Console logs go to Azure Monitor; the diagnostic setting below routes them to the workspace. Logs
    // land in the dedicated ContainerAppConsoleLogs table (not a _CL custom-log table).
    appLogsConfiguration: {
      destination: 'azure-monitor'
    }
    // Workload-profiles environment on a custom VNet: required for UDR / firewall egress control and NAT.
    vnetConfiguration: {
      infrastructureSubnetId: infrastructureSubnetId
      internal: internalOnly
    }
    workloadProfiles: [
      {
        name: workloadProfileName
        workloadProfileType: workloadProfileType
      }
    ]
  }
}

resource envDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'send-app-logs-to-log-analytics'
  scope: env
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      { category: 'ContainerAppConsoleLogs', enabled: true }
    ]
  }
}

@description('Pass to main-functions.bicep as envName (with createEnvironment=false, envResourceGroup=this group).')
output environmentName string = env.name
output environmentId string = env.id
output defaultDomain string = env.properties.defaultDomain
output staticIp string = env.properties.staticIp
