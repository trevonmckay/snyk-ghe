using System.Text.Json;

namespace SnykGhe.Core.Processing
{
    /// <summary>
    /// Envelope for a manually triggered baseline scan queued onto the webhook queue. Rather than
    /// synthesizing a GitHub webhook payload (whose Octokit models require dozens of fields), the manual
    /// endpoint serializes a <see cref="BaselineScanRequest"/> under an internal event name; the dispatcher
    /// recognizes that name and routes the request straight to the baseline scanner.
    /// </summary>
    public static class BaselineScanMessage
    {
        /// <summary>
        /// Internal (non-GitHub) event name. The slash-prefixed vendor namespace cannot collide with a real
        /// GitHub <c>X-GitHub-Event</c> value, so a genuine webhook never routes down the baseline path.
        /// </summary>
        public const string EventName = "x-snyk-ghe/baseline-scan";

        private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);

        public static byte[] Serialize(BaselineScanRequest request) =>
            JsonSerializer.SerializeToUtf8Bytes(request, Options);

        public static BaselineScanRequest? Deserialize(byte[] body) =>
            JsonSerializer.Deserialize<BaselineScanRequest>(body, Options);
    }
}
