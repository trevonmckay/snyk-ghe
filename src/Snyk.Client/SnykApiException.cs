namespace Snyk.Client
{
    /// <summary>An error returned by the Snyk REST API, or a test that reached a terminal error state.</summary>
    public sealed class SnykApiException : Exception
    {
        public SnykApiException(string message)
            : base(message)
        {
        }

        public SnykApiException(string message, int? statusCode, string? errorCode)
            : base(message)
        {
            StatusCode = statusCode;
            ErrorCode = errorCode;
        }

        /// <summary>HTTP status code, when the failure came from a response rather than a test outcome.</summary>
        public int? StatusCode { get; init; }

        /// <summary>Snyk error code (e.g. <c>SNYK-TARGET-0001</c>), when the response carried one.</summary>
        public string? ErrorCode { get; init; }

        /// <summary>
        /// Value of the response's <c>snyk-request-id</c> header, when present. This is the handle Snyk
        /// support uses to trace a request server-side, so it is worth logging on every failure.
        /// </summary>
        public string? RequestId { get; init; }
    }
}
