// Grants AcrPull on an existing Azure Container Registry to a principal. Deployed as a module so the
// role assignment is declared in the registry's own resource group (a role assignment cannot target a
// resource in another resource group from the parent deployment).

@description('Name of the existing Azure Container Registry in this resource group.')
param acrName string

@description('Principal id (managed identity) to grant AcrPull.')
param principalId string

var roleAcrPull = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: acrName
}

resource acrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, principalId, roleAcrPull)
  scope: acr
  properties: {
    roleDefinitionId: roleAcrPull
    principalId: principalId
    principalType: 'ServicePrincipal'
  }
}
