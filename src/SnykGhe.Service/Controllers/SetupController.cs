using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Mvc;

namespace SnykGhe.Service.Controllers
{
    /// <summary>
    /// Post-installation landing page (the App's Setup URL). GitHub redirects a user here after they
    /// install or update the App, passing <c>installation_id</c> and <c>setup_action</c>. The installation
    /// itself is recorded by the <c>installation</c> webhook; this page confirms it and shows the remaining
    /// step — mapping the GitHub org to a Snyk org.
    /// </summary>
    [ApiController]
    public sealed class SetupController : ControllerBase
    {
        [HttpGet("api/github/setup")]
        public IActionResult Setup(
            [FromQuery(Name = "installation_id")] long? installationId,
            [FromQuery(Name = "setup_action")] string? setupAction)
        {
            var action = HtmlEncoder.Default.Encode(setupAction ?? "install");
            var install = installationId?.ToString() ?? "(pending)";
            var baseUrl = HtmlEncoder.Default.Encode($"{Request.Scheme}://{Request.Host}");

            var curl =
                $"curl -X PUT {baseUrl}/api/admin/orgs/&lt;github-org&gt; \\\n" +
                "  -H \"X-Admin-Key: &lt;admin-key&gt;\" -H \"Content-Type: application/json\" \\\n" +
                "  -d '{\"snykOrgId\":\"&lt;snyk-org-uuid&gt;\"}'";

            var html = $$"""
                <!doctype html>
                <html><head><meta charset="utf-8"><title>Snyk GHE — setup</title></head>
                <body>
                  <h1>Snyk GHE installed</h1>
                  <p>Installation <code>{{install}}</code> ({{action}}) is connected. Pull requests will be
                     scanned automatically once this org is mapped to a Snyk org.</p>
                  <p>Map this GitHub org to a Snyk org (run by an operator with the admin key):</p>
                  <pre>{{curl}}</pre>
                </body></html>
                """;

            return Content(html, "text/html; charset=utf-8");
        }
    }
}
