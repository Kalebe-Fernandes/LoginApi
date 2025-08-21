using System.Security.Claims;
using AuthAPI.Domain.Entities;

namespace AuthAPI.Application.Interfaces
{
    // Serviço de Tokens (JWT + Refresh)
    public interface ITokenService
    {
        AccessTokenResult GenerateAccessToken(Guid userId, string email, IEnumerable<string> roles, IDictionary<string, string>? additionalClaims = null);
        RefreshTokenResult CreateRefreshToken(Guid userId, string? createdByIp, TimeSpan? lifetime = null);
        bool ValidateRefreshToken(string plainText, RefreshToken entity);
        ClaimsPrincipal? GetPrincipalFromExpiredAccessToken(string accessToken);
    }
}