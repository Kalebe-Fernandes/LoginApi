using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthAPI.Tests.Tests.TestControllers
{
    [ApiController]
    [Route("__test/jwt")]
    public class TestJwtController : ControllerBase
    {
        [Authorize]
        [HttpGet("claims")]
        public IActionResult Claims()
        {
            var uid = User.FindFirst("UserID")?.Value;
            var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray();
            return Ok(new { userId = uid, roles });
        }
    }
}