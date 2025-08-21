using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthAPI.Application.Interfaces;
using AuthAPI.Infrastructure.Configurations;
using AuthAPI.Infrastructure.Services;
using AuthAPI.Tests.Tests.Shared;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthAPI.Tests.Tests.Unit.Infrastructure
{
    public class JwtTokenServiceTests(TestFixture fixture) : TestBase(fixture), IClassFixture<TestFixture>
    {
        private static ITokenService CreateService(
            string issuer = "authapi.test",
            string audience = "authapi.clients",
            string secret = "THIS_IS_A_32+_CHAR_SECURE_TEST_KEY_123456",
            int accessMinutes = 15,
            int refreshDays = 7,
            int clockSkewSeconds = 5)
        {
            var options = Options.Create(new JwtOptions
            {
                Issuer = issuer,
                Audience = audience,
                SecretKey = secret,
                AccessTokenLifetimeMinutes = accessMinutes,
                RefreshTokenLifetimeDays = refreshDays,
                ClockSkewSeconds = clockSkewSeconds
            });

            return new JwtTokenService(options);
        }

        // GenerateAccessToken

        [Fact]
        public void GenerateAccessToken_ShouldIncludeStandardClaims_AndRoles_Aggregated()
        {
            var svc = CreateService(accessMinutes: 30);
            var userId = Guid.NewGuid();
            var email = "user@test.local";
            var roles = new[] { "User", "Admin" };
            var extra = new Dictionary<string, string> { { "Custom", "ABC" } };

            var result = svc.GenerateAccessToken(userId, email, roles, extra);

            result.Token.Should().NotBeNullOrWhiteSpace();
            result.ExpiresAt.Should().BeAfter(DateTimeOffset.UtcNow.AddMinutes(25)).And.BeBefore(DateTimeOffset.UtcNow.AddMinutes(31));

            // Decode for inspection
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(result.Token);

            jwt.Claims.Should().ContainSingle(c => c.Type == "UserID" && c.Value == userId.ToString());
            jwt.Claims.Should().ContainSingle(c => c.Type == ClaimTypes.NameIdentifier && c.Value == userId.ToString());
            jwt.Claims.Should().Contain(c => c.Type == ClaimTypes.Email && c.Value == email);
            jwt.Claims.Should().Contain(c => c.Type == "Email" && c.Value == email);

            // Role claims present individually
            foreach (var r in roles)
            {
                jwt.Claims.Should().Contain(c => c.Type == ClaimTypes.Role && c.Value == r);
            }

            // Aggregated "Roles" claim
            jwt.Claims.Should().ContainSingle(c => c.Type == "Roles" && c.Value == string.Join(",", roles));

            // Extra claim included
            jwt.Claims.Should().ContainSingle(c => c.Type == "Custom" && c.Value == "ABC");

            // AccessTokenResult.Claims dictionary aggregation
            result.Claims.Should().ContainKey("UserID").WhoseValue.Should().Be(userId.ToString());
            result.Claims.Should().ContainKey(ClaimTypes.Role).WhoseValue.Should().Be(string.Join(",", roles));
            result.Claims.Should().ContainKey("Roles").WhoseValue.Should().Be(string.Join(",", roles));
            result.Claims.Should().ContainKey(ClaimTypes.Email).WhoseValue.Should().Be(email);
            result.Claims.Should().ContainKey("Email").WhoseValue.Should().Be(email);
        }

        [Fact]
        public void GenerateAccessToken_ShouldUse_ConfigurableExpiration()
        {
            var svc = CreateService(accessMinutes: 5);
            var userId = Guid.NewGuid();
            var email = "a@b.c";

            var result = svc.GenerateAccessToken(userId, email, Array.Empty<string>(), null);

            var delta = result.ExpiresAt - DateTimeOffset.UtcNow;
            delta.TotalMinutes.Should().BeGreaterThan(4).And.BeLessOrEqualTo(6);
        }

        [Fact]
        public void GenerateAccessToken_ShouldBeSigned_With_HmacSha256_AndValidate()
        {
            var issuer = "issuer-x";
            var audience = "aud-y";
            var secret = "ANOTHER_32+_CHAR_LONG_SECRET_KEY_XYZ123456";
            var svc = CreateService(issuer: issuer, audience: audience, secret: secret, accessMinutes: 10);

            var userId = Guid.NewGuid();
            var token = svc.GenerateAccessToken(userId, "user@test.local", new[] { "User" });

            // Validate signature and standard params
            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateAudience = true,
                ValidAudience = audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(5)
            };

            var handler = new JwtSecurityTokenHandler();
            var principal = handler.ValidateToken(token.Token, parameters, out var validated);
            principal.Should().NotBeNull();
            validated.Should().BeOfType<JwtSecurityToken>()
                     .Which.Header.Alg.Should().Be(SecurityAlgorithms.HmacSha256);
        }

        // CreateRefreshToken

        [Fact]
        public void CreateRefreshToken_ShouldReturnPlainText_InExpectedFormat_AndUnique()
        {
            var svc = CreateService(refreshDays: 7);
            var userId = Guid.NewGuid();

            var r1 = svc.CreateRefreshToken(userId, "127.0.0.1");
            var r2 = svc.CreateRefreshToken(userId, "127.0.0.1");

            r1.PlainText.Should().MatchRegex(@"^[0-9a-fA-F\-]{32,36}\..+$"); // <guid>.<base64> (Guid N or D)
            r2.PlainText.Should().MatchRegex(@"^[0-9a-fA-F\-]{32,36}\..+$");
            r1.PlainText.Should().NotBe(r2.PlainText);

            r1.ExpiresAt.Should().BeAfter(DateTimeOffset.UtcNow.AddDays(6));
            r2.ExpiresAt.Should().BeAfter(DateTimeOffset.UtcNow.AddDays(6));

            r1.Entity.UserId.Should().Be(userId);
            r1.Entity.TokenHash.Should().NotBeNullOrWhiteSpace();
            r1.Entity.TokenSalt.Should().NotBeNullOrWhiteSpace();
        }

        [Fact]
        public void CreateRefreshToken_ShouldHonor_CustomLifetime()
        {
            var svc = CreateService();
            var userId = Guid.NewGuid();

            var lifetime = TimeSpan.FromHours(3);
            var r = svc.CreateRefreshToken(userId, null, lifetime);

            var diff = r.ExpiresAt - DateTimeOffset.UtcNow;
            diff.TotalHours.Should().BeGreaterThan(2.5).And.BeLessOrEqualTo(3.5);
        }

        // ValidateRefreshToken

        [Fact]
        public void ValidateRefreshToken_ShouldSucceed_ForValidToken()
        {
            var svc = CreateService();
            var userId = Guid.NewGuid();

            var created = svc.CreateRefreshToken(userId, "ip");
            var ok = svc.ValidateRefreshToken(created.PlainText, created.Entity);

            ok.Should().BeTrue();
        }

        [Fact]
        public void ValidateRefreshToken_ShouldFail_ForInvalidFormat()
        {
            var svc = CreateService();
            var token = svc.CreateRefreshToken(Guid.NewGuid(), null);

            svc.ValidateRefreshToken("invalid_format_without_dot", token.Entity).Should().BeFalse();
            svc.ValidateRefreshToken("", token.Entity).Should().BeFalse();
            svc.ValidateRefreshToken(null!, token.Entity).Should().BeFalse();
        }

        [Fact]
        public void ValidateRefreshToken_ShouldFail_ForInvalidSignature_EvenWithSameLength()
        {
            var svc = CreateService();
            var created = svc.CreateRefreshToken(Guid.NewGuid(), "1.1.1.1");

            // Keep Guid part, change secret but preserve length to exercise constant-time compare path
            var parts = created.PlainText.Split('.', 2);
            var secret = parts[1];
            var mutated = new string(secret.Select(ch => ch == 'A' ? 'B' : 'A').ToArray());
            if (mutated.Length != secret.Length)
            {
                mutated = secret.Replace('/', '_'); // keep length
            }

            var tampered = $"{parts[0]}.{mutated}";
            svc.ValidateRefreshToken(tampered, created.Entity).Should().BeFalse();
        }

        [Fact]
        public void ValidateRefreshToken_ShouldFail_ForExpiredToken()
        {
            var svc = CreateService();
            var created = svc.CreateRefreshToken(Guid.NewGuid(), null, lifetime: TimeSpan.FromSeconds(1));

            // Aguarda expirar efetivamente
            Thread.Sleep(1500);

            svc.ValidateRefreshToken(created.PlainText, created.Entity).Should().BeFalse();
        }

        [Fact]
        public void ValidateRefreshToken_ShouldFail_ForRevokedToken()
        {
            var svc = CreateService();
            var created = svc.CreateRefreshToken(Guid.NewGuid(), "ip");

            created.Entity.Revoke("test", "ip");
            svc.ValidateRefreshToken(created.PlainText, created.Entity).Should().BeFalse();
        }

        // GetPrincipalFromExpiredToken

        [Fact]
        public void GetPrincipalFromExpiredToken_ShouldRecoverClaims_FromExpiredToken()
        {
            // Gera token válido (ValidateLifetime=false no método sob teste permite ler mesmo expirado ou não)
            var svc = CreateService(accessMinutes: 1);
            var userId = Guid.NewGuid();
            var email = "user@test.local";
            var roles = new[] { "User", "Support" };

            var access = svc.GenerateAccessToken(userId, email, roles);
            var principal = svc.GetPrincipalFromExpiredAccessToken(access.Token);

            principal.Should().NotBeNull();
            principal!.FindFirst("UserID")!.Value.Should().Be(userId.ToString());
            principal.FindAll(ClaimTypes.Role).Select(r => r.Value).Should().BeEquivalentTo(roles);
        }

        [Fact]
        public void GetPrincipalFromExpiredToken_ShouldReturnNull_ForInvalidSignature()
        {
            // Gera um token com secret diferente (assinatura inválida para o serviço que tenta validar),
            // mantendo mesmo issuer/audience para isolar a causa.
            var issuer = "authapi.test";
            var audience = "authapi.clients";

            var goodSecret = "GOOD_SECRET_KEY_32+_CHARS_abcdef1234567890";
            var badSecret = "BAD__SECRET_KEY_32+_CHARS_abcdef1234567890";

            var svcGood = CreateService(issuer: issuer, audience: audience, secret: goodSecret, accessMinutes: 1);
            var svcBad = CreateService(issuer: issuer, audience: audience, secret: badSecret, accessMinutes: 1);

            var userId = Guid.NewGuid();
            var badToken = svcBad.GenerateAccessToken(userId, "user@test.local", new[] { "User" });

            var principal = svcGood.GetPrincipalFromExpiredAccessToken(badToken.Token);
            principal.Should().BeNull();
        }
    }
}