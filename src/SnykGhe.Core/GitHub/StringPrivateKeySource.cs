using GitHubJwt;

namespace SnykGhe.Core.GitHub
{
    /// <summary>
    /// Supplies a GitHub App PEM private key from an in-memory string so the key can be loaded
    /// from configuration / Key Vault rather than a file on disk.
    /// </summary>
    public sealed class StringPrivateKeySource : IPrivateKeySource
    {
        private readonly string _pem;

        public StringPrivateKeySource(string pem)
        {
            _pem = pem;
        }

        public TextReader GetPrivateKeyReader() => new StringReader(_pem);
    }
}
