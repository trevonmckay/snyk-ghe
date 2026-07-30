using './main-functions.bicep'

// Copy to main-functions.local.bicepparam (gitignored) and fill in, or pass secrets on the CLI.
param baseName = 'snykghe'
param deployerObjectId = '00000000-0000-0000-0000-000000000000' // az ad signed-in-user show --query id -o tsv
param gitHubApiBaseUrl = 'https://api.SUBDOMAIN.ghe.com/'
param gitHubAppId = 0
param snykDefaultOrgId = ''
param snykDefaultSeverity = 'high'
param snykDefaultEcosystem = 'nuget'
// Snyk OAuth client id — a public identifier, not a secret (not stored in Key Vault).
param snykOAuthClientId = ''

// The GitHub App private key and webhook secret are NOT deploy inputs — registration generates them and
// writes them to Key Vault at runtime (call the registrationUrl output after deploying).
// Snyk auth: supply the token, the OAuth pair (id above + secret below), or both. At least one is required.
param snykToken = ''
param snykOAuthClientSecret = ''
param adminApiKey = ''

// --- Optional: reuse existing shared infrastructure ---
// By default the template creates its own registry, Container Apps environment, and Log Analytics
// workspace, all named from baseName. To reuse a centrally-governed / VNet-integrated resource instead,
// flip the matching create* to false and point *Name (plus *ResourceGroup when it lives in another group)
// at it. Any resource name can also be overridden on its own to match a house naming convention.
//
// param createAcr = false
// param acrName = 'sharedregistry'
// param acrResourceGroup = 'rg-platform-containers'
//
// param createEnvironment = false
// param envName = 'cae-shared-eastus2'
// param envResourceGroup = 'rg-platform-containers'
// param workloadProfileName = 'Consumption'   // set when the shared environment is workload-profiles type
//
// param createLogAnalytics = false
// param lawName = 'log-shared'
// param lawResourceGroup = 'rg-platform-logging'
