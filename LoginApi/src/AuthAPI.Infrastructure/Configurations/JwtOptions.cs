namespace AuthAPI.Infrastructure.Configurations
{
    public sealed class JwtOptions
    {
        public const string SectionName = "Jwt";

        // Requerido
        public string Issuer { get; set; } = default!;
        public string Audience { get; set; } = default!;
        public string SecretKey { get; set; } = default!; // 32+ chars para HMAC-SHA256

        // Tempo de vida em minutos para o Access Token
        public int AccessTokenLifetimeMinutes { get; set; } = 15;

        // Tempo de vida em dias para o Refresh Token (padrão seguro)
        public int RefreshTokenLifetimeDays { get; set; } = 7;

        // Tolerância de clock (segundos) para validação
        public int ClockSkewSeconds { get; set; } = 60;
    }
}