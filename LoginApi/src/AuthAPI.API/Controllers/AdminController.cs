using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthAPI.API.Controllers
{
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{version:apiVersion}/admin")]
    [Authorize(Roles = "Admin")]
    public class AdminController : ControllerBase
    {
        // GET /api/v1/admin/dashboard
        [HttpGet("dashboard")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public IActionResult Dashboard()
        {
            // Payload simples demonstrativo; em cenários reais retornar métricas/relatórios
            return Ok(new
            {
                message = "Admin dashboard OK",
                serverTimeUtc = DateTimeOffset.UtcNow
            });
        }
    }
}