using './main.bicep'

// Copy to main.local.bicepparam (gitignored) and fill in, or pass secrets on the CLI.
param baseName = 'snykghe'
param deployerObjectId = '00000000-0000-0000-0000-000000000000' // az ad signed-in-user show --query id -o tsv
param gitHubApiBaseUrl = 'https://api.SUBDOMAIN.ghe.com/'
param gitHubAppId = 0
param snykDefaultOrgId = ''
param snykDefaultSeverity = 'high'
param snykDefaultEcosystem = 'nuget'

// Secrets — leave blank here and pass at deploy time; do not commit real values.
param gitHubPrivateKeyPem = ''
param gitHubWebhookSecret = ''
param snykToken = ''
param adminApiKey = ''
