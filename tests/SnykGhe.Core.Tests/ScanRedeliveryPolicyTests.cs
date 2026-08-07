using SnykGhe.Core.Messaging;

namespace SnykGhe.Core.Tests
{
    public class ScanRedeliveryPolicyTests
    {
        [Theory]
        [InlineData(1, 3)] // first delivery, budget remaining
        [InlineData(2, 3)]
        [InlineData(3, 3)] // at the limit, still retried
        public void ShouldRedeliver_WithinBudget_IsTrue(int deliveryCount, int limit)
        {
            Assert.True(ScanRedeliveryPolicy.ShouldRedeliver(deliveryCount, limit));
        }

        [Theory]
        [InlineData(4, 3)] // one past the limit — give up
        [InlineData(5, 3)]
        [InlineData(1, 0)] // limit 0 gives up on the very first interruption
        public void ShouldRedeliver_BudgetSpent_IsFalse(int deliveryCount, int limit)
        {
            Assert.False(ScanRedeliveryPolicy.ShouldRedeliver(deliveryCount, limit));
        }
    }
}
