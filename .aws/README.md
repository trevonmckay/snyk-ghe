# Infrastructure (AWS / CloudFormation)

`main.yaml` provisions the full AWS footprint for the service, running on **App Runner**: one always-on
compute tier with a durable SQS queue between webhook ingestion and the slow Snyk scan, so a delivery is
never lost if a scan crashes or the instance recycles.

| Resource | Purpose |
| --- | --- |
| App Runner service | Runs the container, managed HTTPS endpoint, autoscaling (always-on, min 1 instance) |
| SQS queue (`snyk-ghe-webhook-deliveries`) | Durable buffer between webhook ingestion and scanning |
| SQS dead-letter queue (`…-dlq`) | Holds deliveries that exhaust the redrive `maxReceiveCount` (5) |
| DynamoDB table (`installations`) | Installation registry |
| Secrets Manager (4 secrets) | App private key, webhook secret, Snyk token, admin key |
| IAM instance role | App's runtime identity (DynamoDB + secret reads + SQS send/receive/delete) |
| IAM access role | Lets App Runner pull from ECR |
| ECR (created out-of-band) | Hosts the image |

The App Runner instance both receives webhooks (validating the HMAC signature) and runs the SQS
background worker that drains the queue and performs scans. App Runner has no scale-to-zero, so the
worker is always present — there is no separate processing tier to wake.

Two env vars steer the runtime, both set by the template: `Storage__Provider=DynamoDb` selects
`DynamoDbGitHubInstallationRegistry`, and `Sqs__QueueUrl` selects the durable SQS webhook queue
(`SqsWebhookQueue` + `SqsWebhookWorker`) over the in-process channel fallback.

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
- **Durability & retries:** a delivery is deleted from SQS only after it processes successfully. A failure leaves it on the queue, so SQS redelivers it after the visibility timeout and moves it to the dead-letter queue after `maxReceiveCount` (5) attempts — at-least-once processing with no silent loss. Inspect failures with `aws sqs receive-message --queue-url <WebhookDeadLetterQueueUrl>`.
- **Visibility timeout:** both the queue and `Sqs__VisibilityTimeoutSeconds` default to 1800s. It must exceed the longest clone + scan; the scan itself is capped by `Snyk__ScanTimeoutSeconds` (600s), so 1800s leaves ample headroom.
- **Secret rotation:** update a secret with `aws secretsmanager put-secret-value`; App Runner picks up the new value on the next deployment/restart.
- **Local development:** with no `Sqs__QueueUrl` the service falls back to an in-process channel queue — no SQS needed to run locally. That queue is **not durable** (queued work is lost on restart), so it is for local/dev only.
