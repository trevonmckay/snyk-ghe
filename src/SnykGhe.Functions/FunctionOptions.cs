namespace SnykGhe.Functions
{
    /// <summary>Configuration for the webhook forwarder Function.</summary>
    public sealed class FunctionOptions
    {
        /// <summary>Shared secret configured on the GitHub App's webhook, used to validate signatures.</summary>
        public string WebhookSecret { get; set; } = string.Empty;
    }
}
