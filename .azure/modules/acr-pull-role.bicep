// Grants image-pull permission on an existing Azure Container Registry to a principal. Deployed as a
// module so the role assignment is declared in the registry's own resource group (a role assignment
// cannot target a resource in another resource group from the parent deployment).
//
// The pull role is parameterized because it depends on the registry's role-assignment permissions
// mode. RBAC-only registries use AcrPull (the default). ABAC-enabled registries
// (roleAssignmentMode=AbacRepositoryPermissions) do NOT honor AcrPull — pass Container Registry
// Repository Reader (b93aa761-3e63-49ed-ac28-beffa264f7ac) instead, or the pull silently 401s.

@description('Name of the existing Azure Container Registry in this resource group.')
param acrName string

@description('Principal id (managed identity) to grant the pull role.')
param principalId string

@description('Role definition guid to grant for image pull. Default AcrPull (RBAC-only registries); use Container Registry Repository Reader b93aa761-3e63-49ed-ac28-beffa264f7ac for ABAC-enabled registries.')
param roleDefinitionId string = '7f951dda-4ed3-4680-a7ca-43fe172d538d'

var pullRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleDefinitionId)

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: acrName
}

resource acrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, principalId, pullRole)
  scope: acr
  properties: {
    roleDefinitionId: pullRole
    principalId: principalId
    principalType: 'ServicePrincipal'
  }
}
