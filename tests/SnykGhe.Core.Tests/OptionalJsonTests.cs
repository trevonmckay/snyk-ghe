using System.Text.Json;
using SnykGhe.Core.Json;

namespace SnykGhe.Core.Tests
{
    public class OptionalJsonTests
    {
        private sealed record Patch
        {
            public Optional<string?> Name { get; init; }

            public Optional<List<string>?> Items { get; init; }
        }

        private static Patch Deserialize(string json) =>
            JsonSerializer.Deserialize<Patch>(json, JsonSerializerOptions.Web)!;

        [Fact]
        public void AbsentMember_IsNotSpecified()
        {
            var patch = Deserialize("{}");

            Assert.False(patch.Name.IsSpecified);
            Assert.False(patch.Items.IsSpecified);
        }

        [Fact]
        public void ExplicitNull_IsSpecifiedWithNullValue()
        {
            var patch = Deserialize("""{ "name": null, "items": null }""");

            Assert.True(patch.Name.IsSpecified);
            Assert.Null(patch.Name.Value);
            Assert.True(patch.Items.IsSpecified);
            Assert.Null(patch.Items.Value);
        }

        [Fact]
        public void PresentValue_IsSpecifiedWithValue()
        {
            var patch = Deserialize("""{ "name": "payments", "items": ["obj", "bin"] }""");

            Assert.True(patch.Name.IsSpecified);
            Assert.Equal("payments", patch.Name.Value);
            Assert.True(patch.Items.IsSpecified);
            Assert.Equal(["obj", "bin"], patch.Items.Value!);
        }

        [Fact]
        public void OneMemberPresent_LeavesOthersUnspecified()
        {
            var patch = Deserialize("""{ "items": [] }""");

            Assert.False(patch.Name.IsSpecified);
            Assert.True(patch.Items.IsSpecified);
            Assert.Empty(patch.Items.Value!);
        }
    }
}
