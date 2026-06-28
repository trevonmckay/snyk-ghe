namespace SnykGhe.WebhookService.Infrastructure
{
    /// <summary>
    /// Removes control characters from untrusted values before they are written to logs,
    /// preventing CR/LF log forging (CWE-117).
    /// </summary>
    public static class LogSanitizer
    {
        public static string Clean(string? value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return "(none)";
            }

            Span<char> buffer = stackalloc char[value.Length];
            var length = 0;
            foreach (var ch in value)
            {
                if (!char.IsControl(ch))
                {
                    buffer[length++] = ch;
                }
            }

            return new string(buffer[..length]);
        }
    }
}
