using AuthAPI.Domain.Entities;

namespace AuthAPI.Application.Interfaces
{
    // Resultado do Refresh Token (texto puro para retorno + entidade persistível)
    public sealed record RefreshTokenResult(
        RefreshToken Entity,
        string PlainText,
        DateTimeOffset ExpiresAt
    );
}