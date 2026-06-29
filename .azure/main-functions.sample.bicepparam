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
