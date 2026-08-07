using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Tests
{
    public class BranchFilterTests
    {
        [Fact]
        public void Matches_EmptyPatterns_ScansEverything()
        {
            Assert.True(BranchFilter.Matches([], "any-branch", "main"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void Matches_BlankBaseRef_FailsOpen(string? baseRef)
        {
            // Never suppress a scan because the base branch could not be determined.
            Assert.True(BranchFilter.Matches(["main"], baseRef, "main"));
        }

        [Theory]
        [InlineData("main", "main", true)]
        [InlineData("main", "develop", false)]
        [InlineData("MAIN", "main", true)]      // pattern matching is case-insensitive
        [InlineData("main", "Main", true)]      // base ref matching is case-insensitive
        public void Matches_ExactName(string pattern, string baseRef, bool expected)
        {
            Assert.Equal(expected, BranchFilter.Matches([pattern], baseRef, defaultBranch: null));
        }

        [Theory]
        [InlineData("release/2.0", true)]
        [InlineData("release/hotfix/1", true)]  // '*' spans '/', which is a literal in the pattern
        [InlineData("release", false)]          // the literal '/' is required
        [InlineData("main", false)]
        public void Matches_Wildcard(string baseRef, bool expected)
        {
            Assert.Equal(expected, BranchFilter.Matches(["release/*"], baseRef, defaultBranch: null));
        }

        [Fact]
        public void Matches_Star_MatchesEverything()
        {
            Assert.True(BranchFilter.Matches(["*"], "anything/at/all", "main"));
        }

        [Fact]
        public void Matches_DefaultToken_ResolvesToDefaultBranch()
        {
            Assert.True(BranchFilter.Matches([BranchFilter.DefaultBranchToken], "develop", defaultBranch: "develop"));
            Assert.False(BranchFilter.Matches([BranchFilter.DefaultBranchToken], "main", defaultBranch: "develop"));
        }

        [Fact]
        public void Matches_DefaultToken_UnknownDefaultBranch_DoesNotMatch()
        {
            Assert.False(BranchFilter.Matches([BranchFilter.DefaultBranchToken], "main", defaultBranch: null));
        }

        [Fact]
        public void Matches_AnyPatternMatches_ReturnsTrue()
        {
            IReadOnlyList<string> patterns = [BranchFilter.DefaultBranchToken, "main", "release/*"];

            Assert.True(BranchFilter.Matches(patterns, "main", "main"));          // literal
            Assert.True(BranchFilter.Matches(patterns, "release/9", "main"));     // wildcard
            Assert.True(BranchFilter.Matches(patterns, "trunk", "trunk"));        // $default
            Assert.False(BranchFilter.Matches(patterns, "feature/x", "main"));    // none
        }

        [Fact]
        public void Sanitize_TrimsDropsBlanksAndDedupesCaseInsensitively()
        {
            IReadOnlyList<string> result = BranchFilter.Sanitize(["  main  ", "", "  ", "MAIN", "release/*"]);

            Assert.Equal(["main", "release/*"], result);
        }

        [Fact]
        public void Sanitize_Null_ReturnsEmpty()
        {
            Assert.Empty(BranchFilter.Sanitize(null));
        }

        [Fact]
        public void JoinSplit_RoundTrips()
        {
            IReadOnlyList<string> patterns = ["$default", "main", "release/*"];

            var stored = BranchFilter.Join(patterns);
            Assert.Equal(patterns, BranchFilter.Split(stored));
        }

        [Fact]
        public void Join_Empty_ReturnsNull_SoTheColumnClears()
        {
            Assert.Null(BranchFilter.Join([]));
            Assert.Empty(BranchFilter.Split(null));
        }
    }
}
