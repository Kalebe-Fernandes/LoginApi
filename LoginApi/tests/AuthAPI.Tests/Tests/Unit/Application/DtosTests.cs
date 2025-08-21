using System.Text.Json;
using AuthAPI.Application.DTOs;
using AuthAPI.Tests.Tests.Shared;
using FluentAssertions;

namespace AuthAPI.Tests.Tests.Unit.Application
{
    public class DtosTests(TestFixture fixture) : TestBase(fixture), IClassFixture<TestFixture>
    {
        private static JsonSerializerOptions JsonOptionsPascal => new()
        {
            PropertyNamingPolicy = null, // API configura PascalCase (null)
            WriteIndented = false
        };

        // AuthResponse

        [Fact]
        public void AuthResponse_Properties_ShouldBeSetCorrectly()
        {
            var now = DateTimeOffset.UtcNow;
            var resp = new AuthResponse("access.jwt", now.AddMinutes(30), "refresh.plain", now.AddDays(7));

            resp.AccessToken.Should().Be("access.jwt");
            resp.ExpiresAt.Should().BeAfter(now);
            resp.RefreshToken.Should().Be("refresh.plain");
            resp.RefreshTokenExpiresAt.Should().BeAfter(now);
        }

        [Fact]
        public void AuthResponse_Should_Serialize_And_Deserialize_WithPascalCase()
        {
            var now = DateTimeOffset.UtcNow;
            var src = new AuthResponse("acc", now.AddMinutes(10), "rt", now.AddDays(2));

            var json = JsonSerializer.Serialize(src, JsonOptionsPascal);
            json.Should().Contain("AccessToken").And.Contain("ExpiresAt").And.Contain("RefreshToken").And.Contain("RefreshTokenExpiresAt");

            var back = JsonSerializer.Deserialize<AuthResponse>(json, JsonOptionsPascal);
            back.Should().NotBeNull();
            back!.Should().BeEquivalentTo(src);
        }

        // UserMeResponse

        [Fact]
        public void UserMeResponse_Properties_ShouldBeSet()
        {
            var userId = Guid.NewGuid();
            var roles = new[] { "User", "Admin" };
            var dto = new UserMeResponse(userId, "user@test.local", "User Teste", DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-20)), roles);

            dto.UserId.Should().Be(userId);
            dto.Email.Should().Be("user@test.local");
            dto.NomeCompleto.Should().Be("User Teste");
            dto.DataDeNascimento.Should().NotBeNull();
            dto.Roles.Should().BeEquivalentTo(roles);
        }

        [Fact]
        public void UserMeResponse_Serialize_WithPascalCase_ShouldContainExpectedFields()
        {
            var dto = new UserMeResponse(Guid.NewGuid(), "e@x.y", "Nome", DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-18)), new[] { "User" });

            var json = JsonSerializer.Serialize(dto, JsonOptionsPascal);
            json.Should().Contain("UserId").And.Contain("Email").And.Contain("NomeCompleto").And.Contain("DataDeNascimento").And.Contain("Roles");

            var back = JsonSerializer.Deserialize<UserMeResponse>(json, JsonOptionsPascal);
            back.Should().NotBeNull();
            back!.Should().BeEquivalentTo(dto);
        }

        // Other DTOs - roundtrip serialization and required property semantics

        [Fact]
        public void RegisterUserRequest_Roundtrip_ShouldPreserveValues()
        {
            var dto = new RegisterUserRequest("user@test.local", "Abcdef12", "Nome Completo", DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-30)));
            var json = JsonSerializer.Serialize(dto, JsonOptionsPascal);
            json.Should().Contain("Email").And.Contain("Password").And.Contain("NomeCompleto").And.Contain("DataDeNascimento");

            var back = JsonSerializer.Deserialize<RegisterUserRequest>(json, JsonOptionsPascal);
            back.Should().NotBeNull();
            back!.Should().BeEquivalentTo(dto);
        }

        [Fact]
        public void LoginRequest_Roundtrip_ShouldPreserveValues()
        {
            var dto = new LoginRequest("user@test.local", "P@ssw0rd!");
            var json = JsonSerializer.Serialize(dto, JsonOptionsPascal);
            json.Should().Contain("Email").And.Contain("Password");

            var back = JsonSerializer.Deserialize<LoginRequest>(json, JsonOptionsPascal);
            back.Should().NotBeNull();
            back!.Should().BeEquivalentTo(dto);
        }

        [Fact]
        public void ConfirmEmailRequest_Roundtrip_ShouldPreserveValues()
        {
            var dto = new ConfirmEmailRequest(Guid.NewGuid().ToString(), "TOKEN");
            var json = JsonSerializer.Serialize(dto, JsonOptionsPascal);
            json.Should().Contain("UserId").And.Contain("Token");

            var back = JsonSerializer.Deserialize<ConfirmEmailRequest>(json, JsonOptionsPascal);
            back.Should().NotBeNull();
            back!.Should().BeEquivalentTo(dto);
        }

        [Fact]
        public void RefreshTokenRequest_Roundtrip_ShouldPreserveValues()
        {
            var dto = new RefreshTokenRequest($"{Guid.NewGuid()}.payload");
            var json = JsonSerializer.Serialize(dto, JsonOptionsPascal);
            json.Should().Contain("RefreshToken");

            var back = JsonSerializer.Deserialize<RefreshTokenRequest>(json, JsonOptionsPascal);
            back.Should().NotBeNull();
            back!.Should().BeEquivalentTo(dto);
        }

        [Fact]
        public void ResetPasswordRequest_Roundtrip_ShouldPreserveValues()
        {
            var dto = new ResetPasswordRequest(Guid.NewGuid().ToString(), "TOKEN", "NewP@ss1");
            var json = JsonSerializer.Serialize(dto, JsonOptionsPascal);
            json.Should().Contain("UserId").And.Contain("Token").And.Contain("NewPassword");

            var back = JsonSerializer.Deserialize<ResetPasswordRequest>(json, JsonOptionsPascal);
            back.Should().NotBeNull();
            back!.Should().BeEquivalentTo(dto);
        }

        [Fact]
        public void ForgotPasswordRequest_Roundtrip_ShouldPreserveValues()
        {
            var dto = new ForgotPasswordRequest("user@test.local");
            var json = JsonSerializer.Serialize(dto, JsonOptionsPascal);
            json.Should().Contain("Email");

            var back = JsonSerializer.Deserialize<ForgotPasswordRequest>(json, JsonOptionsPascal);
            back.Should().NotBeNull();
            back!.Should().BeEquivalentTo(dto);
        }
    }
}