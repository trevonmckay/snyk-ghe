# Infrastructure (AWS / CloudFormation)

`main.yaml` provisions the full AWS footprint for the service, running on **App Runner**.

| Resource | Purpose |
| --- | --- |
| App Runner service | Runs the container, managed HTTPS endpoint, autoscaling |
| DynamoDB table (`installations`) | Installation registry |
| Secrets Manager (4 secrets) | App private key, webhook secret, Snyk token, admin key |
| IAM instance role | App's runtime identity (DynamoDB + secret reads) |
| IAM access role | Lets App Runner pull from ECR |
| ECR (created out-of-band) | Hosts the image |

Set `Storage:Provider=DynamoDb` so the service uses `DynamoDbGitHubInstallationRegistry`. The template sets that env var for you.

## Deploy

```bash
# 1. Create the ECR repo and push the image (App Runner needs the image to exist first)
aws ecr create-repository --repository-name snyk-ghe
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)
REPO="$ACCOUNT.dkr.ecr.$REGION.amazonaws.com/snyk-ghe"
aws ecr get-login-password | docker login --username AWS --password-stdin "$ACCOUNT.dkr.ecr.$REGION.amazonaws.com"
docker build -t "$REPO:1.0.0" -f src/SnykGhe.Service/Dockerfile .
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
- **Credentials:** the container uses the default AWS credential chain, which resolves to the App Runner **instance role** — no access keys in config.
- **Secret rotation:** update a secret with `aws secretsmanager put-secret-value`; App Runner picks up the new value on the next deployment/restart.
