using Microsoft.ApplicationInsights.Channel;
using Microsoft.ApplicationInsights.Extensibility;

namespace SnykGhe.Service
{
    /// <summary>
    /// Stamps a fixed <c>cloud_RoleName</c> on every telemetry item. A Container App has no
    /// <c>WEBSITE_SITE_NAME</c>, so the built-in App Insights role-name initializers leave the field empty
    /// and the processing tier appears as an unnamed node in the Application Map (and buckets under an empty
    /// role in <c>summarize by cloud_RoleName</c> queries). This supplies the name explicitly.
    /// </summary>
    public sealed class RoleNameTelemetryInitializer : ITelemetryInitializer
    {
        private readonly string _roleName;

        public RoleNameTelemetryInitializer(string roleName)
        {
            _roleName = roleName;
        }

        public void Initialize(ITelemetry telemetry)
        {
            if (string.IsNullOrEmpty(telemetry.Context.Cloud.RoleName))
            {
                telemetry.Context.Cloud.RoleName = _roleName;
            }
        }
    }
}
