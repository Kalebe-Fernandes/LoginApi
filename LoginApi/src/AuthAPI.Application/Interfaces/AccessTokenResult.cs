namespace AuthAPI.Application.Interfaces
{
    // Resultado do Access Token
    public sealed record AccessTokenResult(
        string Token,
        DateTimeOffset ExpiresAt,
        IReadOnlyDictionary<string, string> Claims
    );
}