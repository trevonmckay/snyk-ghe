using Amazon;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Storage
{
    /// <summary>
    /// DynamoDB coordination store (AWS equivalent of the Azure Table store). One item per
    /// <c>{owner}/{repo}#{branch}</c> keyed by the lowercased branch key. Conditional expressions provide the
    /// compare-and-set the single-flight lease needs; lease timestamps are epoch milliseconds.
    /// </summary>
    public sealed class DynamoDbScanCoordinationStore : IScanCoordinationStore
    {
        private const string KeyAttribute = "Key";

        private readonly IAmazonDynamoDB _client;
        private readonly StorageOptions _options;

        public DynamoDbScanCoordinationStore(IOptions<StorageOptions> options)
        {
            _options = options.Value;
            _client = string.IsNullOrWhiteSpace(_options.AwsRegion)
                ? new AmazonDynamoDBClient()
                : new AmazonDynamoDBClient(RegionEndpoint.GetBySystemName(_options.AwsRegion));
        }

        private string Table => _options.ScanCoordinationTableName;

        private static string Normalize(string key) => key.ToLowerInvariant();

        private Dictionary<string, AttributeValue> Key(string key) =>
            new() { [KeyAttribute] = new AttributeValue(Normalize(key)) };

        public async Task EnsureCreatedAsync(CancellationToken cancellationToken)
        {
            try
            {
                await _client.DescribeTableAsync(Table, cancellationToken);
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
                TableName = Table,
                BillingMode = BillingMode.PAY_PER_REQUEST,
                KeySchema = [new KeySchemaElement(KeyAttribute, KeyType.HASH)],
                AttributeDefinitions = [new AttributeDefinition(KeyAttribute, ScalarAttributeType.S)],
            }, cancellationToken);

            while (true)
            {
                var description = await _client.DescribeTableAsync(Table, cancellationToken);
                if (description.Table.TableStatus == TableStatus.ACTIVE)
                {
                    return;
                }

                await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
            }
        }

        public async Task<ScanClaim> TryAcquireAsync(string key, string requestedSha, string leaseToken, TimeSpan lease, CancellationToken cancellationToken)
        {
            var existing = await _client.GetItemAsync(Table, Key(key), cancellationToken);
            if (existing.IsItemSet
                && existing.Item.TryGetValue("LastScannedSha", out var last)
                && last.S == requestedSha)
            {
                return ScanClaim.AlreadyScanned; // redelivery or a commit the in-flight scan already covered
            }

            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Always record the latest requested commit so a live holder picks it up when it completes its pass.
            await _client.UpdateItemAsync(new UpdateItemRequest
            {
                TableName = Table,
                Key = Key(key),
                UpdateExpression = "SET RequestedSha = :sha, RequestedAt = :now",
                ExpressionAttributeValues = new Dictionary<string, AttributeValue>
                {
                    [":sha"] = new(requestedSha),
                    [":now"] = new() { N = now.ToString() },
                },
            }, cancellationToken);

            // Claim the lease only if it is free or expired.
            try
            {
                await _client.UpdateItemAsync(new UpdateItemRequest
                {
                    TableName = Table,
                    Key = Key(key),
                    UpdateExpression = "SET LeaseOwner = :owner, LeaseUntil = :until",
                    ConditionExpression = "attribute_not_exists(LeaseUntil) OR LeaseUntil <= :now",
                    ExpressionAttributeValues = new Dictionary<string, AttributeValue>
                    {
                        [":owner"] = new(leaseToken),
                        [":until"] = new() { N = (now + (long)lease.TotalMilliseconds).ToString() },
                        [":now"] = new() { N = now.ToString() },
                    },
                }, cancellationToken);
                return ScanClaim.Acquired;
            }
            catch (ConditionalCheckFailedException)
            {
                return ScanClaim.Coalesced; // a live holder exists
            }
        }

        public async Task<string?> CompletePassAsync(string key, string leaseToken, string requestedSha, string scannedSha, TimeSpan lease, CancellationToken cancellationToken)
        {
            for (var attempt = 0; attempt < 8; attempt++)
            {
                var response = await _client.GetItemAsync(Table, Key(key), cancellationToken);
                if (!response.IsItemSet)
                {
                    return null;
                }

                var item = response.Item;
                if (!item.TryGetValue("LeaseOwner", out var owner) || owner.S != leaseToken)
                {
                    return null; // lease lost — leave the current holder's state alone
                }

                if (!item.TryGetValue("RequestedSha", out var requestedValue) || requestedValue.S is not { } seenRequested)
                {
                    return null;
                }

                var hasNewer = seenRequested != requestedSha;
                var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                // Condition on both the owner and the requested sha so a push that lands between this read and
                // the write fails the condition and forces a retry — never a dropped request.
                var request = new UpdateItemRequest
                {
                    TableName = Table,
                    Key = Key(key),
                    ConditionExpression = "LeaseOwner = :owner AND RequestedSha = :seen",
                    ExpressionAttributeValues = new Dictionary<string, AttributeValue>
                    {
                        [":owner"] = new(leaseToken),
                        [":seen"] = new(seenRequested),
                        [":scanned"] = new(scannedSha),
                    },
                };

                if (hasNewer)
                {
                    request.UpdateExpression = "SET LastScannedSha = :scanned, LeaseUntil = :until";
                    request.ExpressionAttributeValues[":until"] = new() { N = (now + (long)lease.TotalMilliseconds).ToString() };
                }
                else
                {
                    request.UpdateExpression = "SET LastScannedSha = :scanned, LeaseUntil = :past, LeaseOwner = :empty";
                    request.ExpressionAttributeValues[":past"] = new() { N = now.ToString() };
                    request.ExpressionAttributeValues[":empty"] = new(string.Empty);
                }

                try
                {
                    await _client.UpdateItemAsync(request, cancellationToken);
                    return hasNewer ? seenRequested : null;
                }
                catch (ConditionalCheckFailedException)
                {
                    continue; // a push landed concurrently; retry and re-evaluate
                }
            }

            return null; // could not commit; let the lease expire
        }

        public async Task ReleaseAsync(string key, string leaseToken, CancellationToken cancellationToken)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            try
            {
                await _client.UpdateItemAsync(new UpdateItemRequest
                {
                    TableName = Table,
                    Key = Key(key),
                    UpdateExpression = "SET LeaseUntil = :past, LeaseOwner = :empty",
                    ConditionExpression = "LeaseOwner = :owner",
                    ExpressionAttributeValues = new Dictionary<string, AttributeValue>
                    {
                        [":past"] = new() { N = now.ToString() },
                        [":empty"] = new(string.Empty),
                        [":owner"] = new(leaseToken),
                    },
                }, cancellationToken);
            }
            catch (ConditionalCheckFailedException)
            {
                // Not ours (already released or stolen) — nothing to do.
            }
        }
    }
}
