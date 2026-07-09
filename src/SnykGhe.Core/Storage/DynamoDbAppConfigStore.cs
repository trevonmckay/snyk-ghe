using Amazon;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Storage
{
    /// <summary>
    /// DynamoDB implementation of <see cref="IAppConfigStore"/>, sharing the installations table. The
    /// item key uses a reserved prefix that cannot collide with a GitHub org login (logins are
    /// alphanumeric + hyphens). Credentials come from the default AWS chain (instance/task role).
    /// </summary>
    public sealed class DynamoDbAppConfigStore : IAppConfigStore
    {
        private const string KeyAttribute = "Org";
        private const string ValueAttribute = "Value";
        private const string AppIdKey = "$appconfig:github-app-id";

        private readonly IAmazonDynamoDB _client;
        private readonly StorageOptions _options;

        public DynamoDbAppConfigStore(IOptions<StorageOptions> options)
        {
            _options = options.Value;
            _client = string.IsNullOrWhiteSpace(_options.AwsRegion)
                ? new AmazonDynamoDBClient()
                : new AmazonDynamoDBClient(RegionEndpoint.GetBySystemName(_options.AwsRegion));
        }

        public async Task<string?> GetAppIdAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var response = await _client.GetItemAsync(
                    _options.TableName,
                    new Dictionary<string, AttributeValue> { [KeyAttribute] = new AttributeValue(AppIdKey) },
                    cancellationToken);

                return response.IsItemSet && response.Item.TryGetValue(ValueAttribute, out var value) ? value.S : null;
            }
            catch (ResourceNotFoundException)
            {
                // Table not created yet; treat as unset.
                return null;
            }
        }

        public async Task SetAppIdAsync(string appId, CancellationToken cancellationToken = default)
        {
            await _client.PutItemAsync(
                _options.TableName,
                new Dictionary<string, AttributeValue>
                {
                    [KeyAttribute] = new AttributeValue(AppIdKey),
                    [ValueAttribute] = new AttributeValue(appId),
                },
                cancellationToken);
        }
    }
}
