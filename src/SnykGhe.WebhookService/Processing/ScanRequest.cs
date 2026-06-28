namespace SnykGhe.WebhookService.Processing
{
    /// <summary>A unit of work: scan one pull request head and report results back to GitHub.</summary>
    public sealed record ScanRequest(
        long InstallationId,
        string Owner,
        string Repo,
        string CloneUrl,
        int PrNumber,
        string HeadRef,
        string HeadSha);
}
