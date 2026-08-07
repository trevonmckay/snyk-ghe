namespace SnykGhe.Core.Messaging
{
    /// <summary>
    /// Decides whether a scan interrupted by host shutdown (<see cref="Snyk.ScanInterruptedException"/>)
    /// should be redelivered again or given up on. A scale-in that keeps recurring (a scan longer than the KEDA
    /// scale-to-zero cooldown) would otherwise re-interrupt every redelivery and loop to the queue's
    /// max-delivery-count / dead-letter. Bounding the retries by delivery count keeps the loop finite and
    /// leaves the posted "could not complete" check as the terminal state instead of a silent dead-letter.
    /// </summary>
    internal static class ScanRedeliveryPolicy
    {
        /// <summary>
        /// True while the delivery/receive count is at or below <paramref name="redeliveryLimit"/> — i.e. the
        /// interrupted scan still has retry budget and should be redelivered. False once the budget is spent.
        /// </summary>
        public static bool ShouldRedeliver(int deliveryCount, int redeliveryLimit) =>
            deliveryCount <= redeliveryLimit;
    }
}
