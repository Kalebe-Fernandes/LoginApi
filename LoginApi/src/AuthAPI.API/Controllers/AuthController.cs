using System.Net;
using AuthAPI.Application.DTOs;
using AuthAPI.Application.Handlers;
using AuthAPI.Application.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthAPI.API.Controllers
{
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{version:apiVersion}/auth")]
    public class AuthController(IUnitOfWork uow, ITokenService tokens, IEmailService emails) : ControllerBase
    {
        private readonly IUnitOfWork _uow = uow;
        private readonly ITokenService _tokens = tokens;
        private readonly IEmailService _emails = emails;

        // POST /api/v1/auth/register
        [HttpPost("register")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(object), StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> Register([FromBody] RegisterUserRequest request, CancellationToken ct)
        {
            var handler = new RegisterUserCommandHandler(_uow.Users, _uow);
            var result = await handler.Handle(new RegisterUserCommand(
                request.Email,
                request.Password,
                request.NomeCompleto,
                request.DataDeNascimento
            ), ct);

            // Envia email de confirmação
            var confirmLink = BuildAbsoluteUrl($"/api/v1/auth/confirm-email?userId={result.UserId}&token={WebUtility.UrlEncode(result.EmailConfirmationToken)}");
            await _emails.SendEmailConfirmationAsync(request.Email, confirmLink, request.NomeCompleto, ct);

            return Created(string.Empty, new { userId = result.UserId });
        }

        // POST /api/v1/auth/confirm-email
        [HttpPost("confirm-email")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailRequest request, CancellationToken ct)
        {
            if (!Guid.TryParse(request.UserId, out var userId))
                return BadRequest(new ProblemDetails { Title = "Invalid userId" });

            await _uow.Users.ConfirmEmailAsync(userId, request.Token, ct);
            return Ok(new { message = "Email confirmado com sucesso." });
        }

        // POST /api/v1/auth/login
        [HttpPost("login")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken ct)
        {
            var handler = new LoginQueryHandler(_uow.Users, _tokens);
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
            var result = await handler.Handle(new LoginQuery(request.Email, request.Password, ip), ct);
            return Ok(result.Response);
        }

        // POST /api/v1/auth/refresh-token
        [HttpPost("refresh-token")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(request.RefreshToken))
                return Unauthorized(new ProblemDetails { Title = "Invalid refresh token" });

            var parts = request.RefreshToken.Split('.', 2);
            if (parts.Length != 2 || !Guid.TryParse(parts[0], out var tokenId))
                return Unauthorized(new ProblemDetails { Title = "Invalid refresh token format" });

            var entity = await _uow.Users.GetRefreshTokenAsync(tokenId, ct);
            if (entity is null)
                return Unauthorized(new ProblemDetails { Title = "Refresh token not found" });

            var valid = _tokens.ValidateRefreshToken(request.RefreshToken, entity);
            if (!valid)
            {
                // Revoke chain for security
                await _uow.Users.RevokeTokenCascadeAsync(entity, "Invalid refresh attempt", HttpContext.Connection.RemoteIpAddress?.ToString(), ct);
                return Unauthorized(new ProblemDetails { Title = "Invalid refresh token" });
            }

            // Token válido: rotacionar
            var email = await _uow.Users.GetEmailByUserIdAsync(entity.UserId, ct) ?? string.Empty;
            var roles = await _uow.Users.GetRolesAsync(entity.UserId, ct);
            var access = _tokens.GenerateAccessToken(entity.UserId, email, roles);

            var newRefresh = _tokens.CreateRefreshToken(entity.UserId, HttpContext.Connection.RemoteIpAddress?.ToString(), null);

            // Marcar o antigo como substituído e revogado
            entity.ReplaceBy(newRefresh.Entity.Id, "Rotated");
            await _uow.Users.UpdateRefreshTokenAsync(entity, ct);

            // Persistir novo refresh
            await _uow.Users.AddRefreshTokenAsync(newRefresh.Entity, ct);

            var resp = new AuthResponse(
                access.Token,
                access.ExpiresAt,
                newRefresh.PlainText,
                newRefresh.ExpiresAt
            );

            return Ok(resp);
        }

        // POST /api/v1/auth/forgot-password
        [HttpPost("forgot-password")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request, CancellationToken ct)
        {
            var userId = await _uow.Users.GetUserIdByEmailAsync(request.Email, ct);
            if (userId is null)
            {
                // Para não revelar se existe ou não
                return Ok(new { message = "Se o email existir, uma mensagem foi enviada." });
            }

            var token = await _uow.Users.GeneratePasswordResetTokenAsync(userId.Value, ct);
            var resetLink = BuildAbsoluteUrl($"/api/v1/auth/reset-password?userId={userId.Value}&token={WebUtility.UrlEncode(token)}");
            await _emails.SendPasswordResetAsync(request.Email, resetLink, null, ct);

            return Ok(new { message = "Se o email existir, uma mensagem foi enviada." });
        }

        // POST /api/v1/auth/reset-password
        [HttpPost("reset-password")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request, CancellationToken ct)
        {
            if (!Guid.TryParse(request.UserId, out var userId))
                return BadRequest(new ProblemDetails { Title = "Invalid userId" });

            await _uow.Users.ResetPasswordAsync(userId, request.Token, request.NewPassword, ct);
            return Ok(new { message = "Senha redefinida com sucesso." });
        }

        // POST /api/v1/auth/logout
        // Invalida (revoga em cascata) a cadeia do refresh token recebido
        [HttpPost("logout")]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<IActionResult> Logout([FromBody] RefreshTokenRequest request, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(request.RefreshToken))
                return Ok();

            var parts = request.RefreshToken.Split('.', 2);
            if (parts.Length == 2 && Guid.TryParse(parts[0], out var tokenId))
            {
                var entity = await _uow.Users.GetRefreshTokenAsync(tokenId, ct);
                if (entity != null)
                {
                    await _uow.Users.RevokeTokenCascadeAsync(entity, "Logout", HttpContext.Connection.RemoteIpAddress?.ToString(), ct);
                }
            }

            return Ok(new { message = "Sessão encerrada." });
        }

        private string BuildAbsoluteUrl(string relativePath)
        {
            var scheme = Request.Scheme;
            var host = Request.Host.Value;
            var pathBase = Request.PathBase.Value?.TrimEnd('/') ?? string.Empty;
            var path = relativePath.StartsWith("/") ? relativePath : "/" + relativePath;
            return $"{scheme}://{host}{pathBase}{path}";
        }
    }
}