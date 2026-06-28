using Microsoft.AspNetCore.Mvc;

namespace SnykGhe.Service.Controllers
{
    [ApiController]
    [Route("healthz")]
    public sealed class HealthController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get() => Ok(new { status = "ok" });
    }
}