using Amazon;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Microsoft.Extensions.Options;
using SnykGhe.WebhookService.Configuration;

namespace SnykGhe.WebhookService.Storage
{
    /// <summary>
    /// DynamoDB-backed installation registry (AWS equivalent of the Azure Table Storage registry).
    /// One item per GitHub org keyed by the normalized org login. Update expressions touch only the
    /// fields each operation owns, so seeding never clobbers an explicit Snyk mapping and vice versa.
    /// Credentials come from the default AWS chain (App Runner / ECS task role).
    /// </summary>
    public sealed class DynamoDbGitHubInstallationRegistry : IGitHubInstallationRegistry
    {
        private const string KeyAttribute = "Org";

        private readonly IAmazonDynamoDB _client;
        private readonly StorageOptions _options;

        public DynamoDbGitHubInstallationRegistry(IOptions<StorageOptions> options)
        {
            _options = options.Value;
            _client = string.IsNullOrWhiteSpace(_options.AwsRegion)
                ? new AmazonDynamoDBClient()
                : new AmazonDynamoDBClient(RegionEndpoint.GetBySystemName(_options.AwsRegion));
        }

        private static string Normalize(string gitHubOrg) => gitHubOrg.ToLowerInvariant();

        private Dictionary<string, AttributeValue> Key(string gitHubOrg) =>
            new() { [KeyAttribute] = new AttributeValue(Normalize(gitHubOrg)) };

        public async Task EnsureCreatedAsync(CancellationToken cancellationToken)
        {
            try
            {
                await _client.DescribeTableAsync(_options.TableName, cancellationToken);
                return;
            }
            catch (ResourceNotFoundException)
            {
                if (!_options.CreateTableIfMissing)
                {
                    throw;
                }
            }

            await _client.CreateTableAsync(new CreateTableRequest
            {
                TableName = _options.TableName,
                BillingMode = BillingMode.PAY_PER_REQUEST,
                KeySchema = [new KeySchemaElement(KeyAttribute, KeyType.HASH)],
                AttributeDefinitions = [new AttributeDefinition(KeyAttribute, ScalarAttributeType.S)],
            }, cancellationToken);

            // Wait until the table is usable.
            while (true)
            {
                var description = await _client.DescribeTableAsync(_options.TableName, cancellationToken);
                if (description.Table.TableStatus == TableStatus.ACTIVE)
                {
                    return;
                }

                await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
            }
        }

        public async Task SeedAsync(long installationId, string gitHubOrg, long accountId, CancellationToken cancellationToken)
        {
            // Only the GitHub-known fields are set, leaving any existing Snyk mapping/policy intact.
            await _client.UpdateItemAsync(new UpdateItemRequest
            {
                TableName = _options.TableName,
                Key = Key(gitHubOrg),
                UpdateExpression = "SET #iid = :iid, #org = :org, #acc = :acc, #susp = :susp",
                ExpressionAttributeNames = new Dictionary<string, string>
                {
                    ["#iid"] = "InstallationId",
                    ["#org"] = "GitHubOrg",
                    ["#acc"] = "AccountId",
                    ["#susp"] = "Suspended",
                },
                ExpressionAttributeValues = new Dictionary<string, AttributeValue>
                {
                    [":iid"] = new() { N = installationId.ToString() },
                    [":org"] = new(gitHubOrg),
                    [":acc"] = new() { N = accountId.ToString() },
                    [":susp"] = new() { BOOL = false },
                },
            }, cancellationToken);
        }

        public async Task SetMappingAsync(string gitHubOrg, string snykOrgId, string? severityThreshold, string? ecosystem, CancellationToken cancellationToken)
        {
            var sets = new List<string> { "#org = :org", "#snyk = :snyk" };
            var names = new Dictionary<string, string> { ["#org"] = "GitHubOrg", ["#snyk"] = "SnykOrgId" };
            var values = new Dictionary<string, AttributeValue> { [":org"] = new(gitHubOrg), [":snyk"] = new(snykOrgId) };

            if (!string.IsNullOrWhiteSpace(severityThreshold))
            {
                sets.Add("#sev = :sev");
                names["#sev"] = "SeverityThreshold";
                values[":sev"] = new(severityThreshold);
            }

            if (!string.IsNullOrWhiteSpace(ecosystem))
            {
                sets.Add("#eco = :eco");
                names["#eco"] = "Ecosystem";
                values[":eco"] = new(ecosystem);
            }

            await _client.UpdateItemAsync(new UpdateItemRequest
            {
                TableName = _options.TableName,
                Key = Key(gitHubOrg),
                UpdateExpression = "SET " + string.Join(", ", sets),
                ExpressionAttributeNames = names,
                ExpressionAttributeValues = values,
            }, cancellationToken);
        }

        public async Task SetSuspendedAsync(string gitHubOrg, bool suspended, CancellationToken cancellationToken)
        {
            await _client.UpdateItemAsync(new UpdateItemRequest
            {
                TableName = _options.TableName,
                Key = Key(gitHubOrg),
                UpdateExpression = "SET #org = :org, #susp = :susp",
                ExpressionAttributeNames = new Dictionary<string, string> { ["#org"] = "GitHubOrg", ["#susp"] = "Suspended" },
                ExpressionAttributeValues = new Dictionary<string, AttributeValue>
                {
                    [":org"] = new(gitHubOrg),
                    [":susp"] = new() { BOOL = suspended },
                },
            }, cancellationToken);
        }

        public async Task RemoveAsync(string gitHubOrg, CancellationToken cancellationToken)
        {
            await _client.DeleteItemAsync(_options.TableName, Key(gitHubOrg), cancellationToken);
        }

        public async Task<GitHubInstallationRecord?> FindAsync(string gitHubOrg, CancellationToken cancellationToken)
        {
            var response = await _client.GetItemAsync(_options.TableName, Key(gitHubOrg), cancellationToken);
            if (!response.IsItemSet)
            {
                return null;
            }

            var item = response.Item;
            return new GitHubInstallationRecord
            {
                InstallationId = GetLong(item, "InstallationId"),
                GitHubOrg = GetString(item, "GitHubOrg") ?? string.Empty,
                AccountId = GetLong(item, "AccountId"),
                SnykOrgId = GetString(item, "SnykOrgId"),
                SeverityThreshold = GetString(item, "SeverityThreshold"),
                Ecosystem = GetString(item, "Ecosystem"),
                Suspended = item.TryGetValue("Suspended", out var s) && s.IsBOOLSet && s.BOOL == true,
            };
        }

        private static string? GetString(IReadOnlyDictionary<string, AttributeValue> item, string name) =>
            item.TryGetValue(name, out var value) ? value.S : null;

        private static long GetLong(IReadOnlyDictionary<string, AttributeValue> item, string name) =>
            item.TryGetValue(name, out var value) && long.TryParse(value.N, out var parsed) ? parsed : 0;
    }
}
