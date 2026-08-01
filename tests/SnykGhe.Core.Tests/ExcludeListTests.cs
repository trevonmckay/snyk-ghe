using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Tests
{
    public class ExcludeListTests
    {
        [Theory]
        [InlineData("src/nested", true)]
        [InlineData("a\\b", true)]
        [InlineData("docling-sidecar", false)]
        [InlineData("obj", false)]
        public void IsPathLike_FlagsPathSeparators(string entry, bool expected)
        {
            Assert.Equal(expected, ExcludeList.IsPathLike(entry));
        }

        [Fact]
        public void Sanitize_TrimsDropsBlanksAndPathsAndDedupes_PreservingOrder()
        {
            var result = ExcludeList.Sanitize(["  obj  ", "obj", "", "  ", "src/skip", "bin\\skip", "docling-sidecar"]);

            Assert.Equal(["obj", "docling-sidecar"], result);
        }

        [Fact]
        public void Sanitize_Null_ReturnsEmpty()
        {
            Assert.Empty(ExcludeList.Sanitize(null));
        }

        [Fact]
        public void JoinThenSplit_RoundTrips()
        {
            IReadOnlyList<string> original = ["obj", "docling-sidecar", "packages"];

            var joined = ExcludeList.Join(original);
            var split = ExcludeList.Split(joined);

            Assert.Equal(original, split);
        }

        [Fact]
        public void Join_Empty_ReturnsNull()
        {
            Assert.Null(ExcludeList.Join([]));
            Assert.Null(ExcludeList.Join(null));
        }

        [Fact]
        public void Split_NullOrEmpty_ReturnsEmpty()
        {
            Assert.Empty(ExcludeList.Split(null));
            Assert.Empty(ExcludeList.Split(""));
        }
    }
}
