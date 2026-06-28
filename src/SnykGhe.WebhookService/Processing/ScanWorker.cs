namespace SnykGhe.WebhookService.Processing
{
    /// <summary>Drains the scan queue and processes each pull request request sequentially.</summary>
    public sealed class ScanWorker : BackgroundService
    {
        private readonly IScanQueue _queue;
        private readonly PullRequestCheckService _prCheckService;
        private readonly ILogger _logger;

        public ScanWorker(
            IScanQueue queue,
            PullRequestCheckService checkService,
            ILogger<ScanWorker> logger)
        {
            this._queue = queue;
            this._prCheckService = checkService;
            this._logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await foreach (var request in _queue.DequeueAllAsync(stoppingToken))
            {
                try
                {
                    await _prCheckService.ProcessAsync(request, stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to process scan for {Owner}/{Repo} PR #{Pr}",
                        request.Owner, request.Repo, request.PrNumber);
                }
            }
        }
    }
}
