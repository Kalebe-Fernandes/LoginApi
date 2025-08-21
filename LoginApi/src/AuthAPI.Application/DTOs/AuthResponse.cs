namespace AuthAPI.Application.DTOs
{
    // Respostas
    public record AuthResponse(
        string AccessToken,
        DateTimeOffset ExpiresAt,
        string RefreshToken,
        DateTimeOffset RefreshTokenExpiresAt
    );
}