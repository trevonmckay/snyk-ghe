# Infrastructure (AWS / CloudFormation)

`main.yaml` provisions the AWS equivalent of the Azure stack, for running the service on **App Runner**.

| Resource | Purpose | Azure equivalent |
| --- | --- | --- |
| App Runner service | Runs the container, managed HTTPS endpoint, autoscaling | Container Apps |
| DynamoDB table (`installations`) | Installation registry | Storage Table |
| Secrets Manager (4 secrets) | App private key, webhook secret, Snyk token, admin key | Key Vault |
| IAM instance role | App's runtime identity (DynamoDB + secret reads) | Managed identity |
| IAM access role | Lets App Runner pull from ECR | AcrPull role |
| ECR (created out-of-band) | Hosts the image | ACR |

The app runs unchanged on either cloud — set `Storage:Provider=DynamoDb` and it uses `DynamoDbGitHubInstallationRegistry` instead of the Table Storage one. The template sets that env var for you.

## Deploy

```bash
# 1. Create the ECR repo and push the image (App Runner needs the image to exist first)
aws ecr create-repository --repository-name snyk-ghe
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)
REPO="$ACCOUNT.dkr.ecr.$REGION.amazonaws.com/snyk-ghe"
aws ecr get-login-password | docker login --username AWS --password-stdin "$ACCOUNT.dkr.ecr.$REGION.amazonaws.com"
docker build -t "$REPO:1.0.0" -f src/SnykGhe.WebhookService/Dockerfile .
docker push "$REPO:1.0.0"

# 2. Deploy the stack (secrets passed as parameters; keep them out of shell history where possible)
aws cloudformation deploy \
  --stack-name snyk-ghe \
  --template-file .aws/main.yaml \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    ContainerImageUri="$REPO:1.0.0" \
    GitHubApiBaseUrl="https://api.SUBDOMAIN.ghe.com/" \
    GitHubAppId=<app-id> \
    GitHubPrivateKeyPem="$(cat app-private-key.pem)" \
    GitHubWebhookSecret=<secret> \
    SnykToken=<token> \
    AdminApiKey=<key>

# 3. Read the webhook URL to configure on the GitHub App
aws cloudformation describe-stacks --stack-name snyk-ghe \
  --query "Stacks[0].Outputs[?OutputKey=='WebhookUrl'].OutputValue" --output text
```

## Notes

- **`CAPABILITY_IAM`** is required because the stack creates the two IAM roles.
- **No CreateTable at runtime:** the stack pre-creates the DynamoDB table and sets `Storage__CreateTableIfMissing=false`, so the instance role only needs data + `DescribeTable` permissions (least privilege).
- **Credentials:** the container uses the default AWS credential chain, which resolves to the App Runner **instance role** — no access keys in config, mirroring the Azure managed-identity approach.
- **Secret rotation:** update a secret with `aws secretsmanager put-secret-value`; App Runner picks up the new value on the next deployment/restart.
- **Moving to Azure later:** redeploy `.azure/main.bicep` and set `Storage:Provider=AzureTable` (the default). No code changes.
