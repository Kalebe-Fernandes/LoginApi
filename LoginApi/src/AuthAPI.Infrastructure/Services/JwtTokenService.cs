using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthAPI.Application.Interfaces;
using AuthAPI.Domain.Entities;
using AuthAPI.Infrastructure.Configurations;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthAPI.Infrastructure.Services
{
    public sealed class JwtTokenService : ITokenService
    {
        private readonly JwtOptions _options;
        private readonly SymmetricSecurityKey _signingKey;

        public JwtTokenService(IOptions<JwtOptions> options)
        {
            _options = options.Value;
            if (string.IsNullOrWhiteSpace(_options.SecretKey) || _options.SecretKey.Length < 32)
                throw new InvalidOperationException("Jwt:SecretKey inválida. Defina uma chave com 32+ caracteres via User Secrets.");

            _signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SecretKey));
        }

        public AccessTokenResult GenerateAccessToken(Guid userId, string email, IEnumerable<string> roles, IDictionary<string, string>? additionalClaims = null)
        {
            var now = DateTimeOffset.UtcNow;
            var expires = now.AddMinutes(_options.AccessTokenLifetimeMinutes);

            var claims = new List<Claim>
            {
                new("UserID", userId.ToString()),
                new(ClaimTypes.NameIdentifier, userId.ToString()),
                new(ClaimTypes.Email, email),
                new("Email", email),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N"))
            };

            var roleList = roles?.ToList() ?? new List<string>();
            foreach (var r in roleList)
            {
                if (!string.IsNullOrWhiteSpace(r))
                    claims.Add(new Claim(ClaimTypes.Role, r));
            }

            // Claim agregada de roles (útil para debug/clients)
            if (roleList.Count > 0)
                claims.Add(new Claim("Roles", string.Join(",", roleList)));

            if (additionalClaims != null)
            {
                foreach (var kv in additionalClaims)
                {
                    claims.Add(new Claim(kv.Key, kv.Value));
                }
            }

            var creds = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: _options.Issuer,
                audience: _options.Audience,
                claims: claims,
                notBefore: now.UtcDateTime,
                expires: expires.UtcDateTime,
                signingCredentials: creds
            );

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            var claimsDict = claims
                .GroupBy(c => c.Type)
                .ToDictionary(g => g.Key, g => string.Join(",", g.Select(c => c.Value)));

            return new AccessTokenResult(tokenString, expires, claimsDict);
        }

        public RefreshTokenResult CreateRefreshToken(Guid userId, string? createdByIp, TimeSpan? lifetime = null)
        {
            var ttl = lifetime ?? TimeSpan.FromDays(_options.RefreshTokenLifetimeDays);
            var expires = DateTimeOffset.UtcNow.Add(ttl);

            // Segredo (parte confidencial entregue ao cliente) + salt armazenado e hashado
            var secret = GenerateSecret(64); // base64
            var salt = GenerateSecret(16);   // base64
            var hash = ComputeHash(secret, salt);

            var entity = new RefreshToken(userId, hash, salt, expires, createdByIp);

            // Para lookup eficiente sem armazenar o segredo: prefixamos com o Id do token
            var plainText = $"{entity.Id:N}.{secret}";

            return new RefreshTokenResult(entity, plainText, expires);
        }

        public bool ValidateRefreshToken(string plainText, RefreshToken entity)
        {
            if (entity is null) return false;
            if (string.IsNullOrWhiteSpace(plainText)) return false;

            // Espera-se o formato: <tokenId>.<secretBase64>
            var parts = plainText.Split('.', 2);
            if (parts.Length != 2) return false;

            if (!Guid.TryParse(parts[0], out var providedId)) return false;
            if (providedId != entity.Id) return false;

            var providedSecret = parts[1];
            var computed = ComputeHash(providedSecret, entity.TokenSalt);

            if (!TimeConstantEquals(computed, entity.TokenHash)) return false;
            if (!entity.IsActive) return false;

            return true;
        }

        public ClaimsPrincipal? GetPrincipalFromExpiredAccessToken(string accessToken)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = _options.Issuer,
                ValidateAudience = true,
                ValidAudience = _options.Audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _signingKey,
                // Permite obter principal mesmo se expirado
                ValidateLifetime = false,
                ClockSkew = TimeSpan.FromSeconds(_options.ClockSkewSeconds)
            };

            var handler = new JwtSecurityTokenHandler();
            try
            {
                var principal = handler.ValidateToken(accessToken, tokenValidationParameters, out var securityToken);
                if (securityToken is not JwtSecurityToken jwt
                    || !jwt.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.OrdinalIgnoreCase))
                    return null;

                return principal;
            }
            catch
            {
                return null;
            }
        }

        private static string GenerateSecret(int byteLength)
        {
            var bytes = RandomNumberGenerator.GetBytes(byteLength);
            return Convert.ToBase64String(bytes);
        }

        private static string ComputeHash(string secretBase64, string saltBase64)
        {
            var secretBytes = Convert.FromBase64String(secretBase64);
            var saltBytes = Convert.FromBase64String(saltBase64);

            // HMAC-SHA256 usando o salt como chave
            using var hmac = new HMACSHA256(saltBytes);
            var hash = hmac.ComputeHash(secretBytes);
            return Convert.ToBase64String(hash);
        }

        private static bool TimeConstantEquals(string a, string b)
        {
            var aBytes = Encoding.UTF8.GetBytes(a);
            var bBytes = Encoding.UTF8.GetBytes(b);

            // Comparação com tempo constante para evitar timing attacks
            int diff = aBytes.Length ^ bBytes.Length;
            for (int i = 0; i < Math.Min(aBytes.Length, bBytes.Length); i++)
            {
                diff |= aBytes[i] ^ bBytes[i];
            }
            return diff == 0;
        }
    }
}