using System.Security.Claims;
using AuthAPI.Application.DTOs;
using AuthAPI.Application.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthAPI.API.Controllers
{
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{version:apiVersion}/users")]
    public class UsersController(IUnitOfWork unitOfWork) : ControllerBase
    {
        private readonly IUnitOfWork _uof = unitOfWork;

        // GET /api/v1/users/me
        [HttpGet("me")]
        [Authorize]
        [ProducesResponseType(typeof(UserMeResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Me(CancellationToken ct)
        {
            var userIdClaim = User.FindFirst("UserID")?.Value ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrWhiteSpace(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                return Unauthorized(new ProblemDetails { Title = "Invalid token claims" });
            }

            var email = await _uof.Users.GetEmailByUserIdAsync(userId, ct) ?? string.Empty;
            var profile = await _uof.Users.GetProfileAsync(userId, ct);
            var roles = await _uof.Users.GetRolesAsync(userId, ct);

            var dto = new UserMeResponse(
                userId,
                email,
                profile?.NomeCompleto ?? string.Empty,
                profile?.DataDeNascimento,
                roles
            );

            return Ok(dto);
        }
    }
}