namespace SnykGhe.WebhookService.Processing
{
    /// <summary>A unit of work: scan one pull request head and report results back to GitHub.</summary>
    public sealed record ScanRequest
    {
        public required long InstallationId { get; init; }
        public required string Owner { get; init; }
        public required string Repo { get; init; }
        public required string CloneUrl { get; init; }
        public required int PrNumber { get; init; }
        public required string HeadRef { get; init; }
        public required string HeadSha { get; init; }
    }
}
