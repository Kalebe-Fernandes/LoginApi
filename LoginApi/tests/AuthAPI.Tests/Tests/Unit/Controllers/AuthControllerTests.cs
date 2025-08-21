using System.Net;
using System.Security.Claims;
using AutoFixture;
using AuthAPI.API.Controllers;
using AuthAPI.Application.DTOs;
using AuthAPI.Application.Interfaces;
using AuthAPI.Domain.Entities;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using AuthAPI.Tests.Tests.Shared;

namespace AuthAPI.Tests.Tests.Unit.Controllers
{
    public class AuthControllerTests : TestBase, IClassFixture<TestFixture>
    {
        private readonly Mock<IUnitOfWork> _uow = new();
        private readonly Mock<IUserRepository> _users = new();
        private readonly Mock<ITokenService> _tokens = new();
        private readonly Mock<IEmailService> _emails = new();

        public AuthControllerTests(TestFixture fixture) : base(fixture)
        {
            _uow.SetupGet(u => u.Users).Returns(_users.Object);
        }

        private AuthController CreateController(string scheme = "https", string host = "test.local", string ip = "127.0.0.1")
        {
            var http = new DefaultHttpContext();
            http.Request.Scheme = scheme;
            http.Request.Host = new HostString(host);
            http.Connection.RemoteIpAddress = IPAddress.Parse(ip);

            var controller = new AuthController(_uow.Object, _tokens.Object, _emails.Object)
            {
                ControllerContext = new ControllerContext { HttpContext = http }
            };

            return controller;
        }

        // POST /auth/register
        [Fact]
        public async Task Register_ShouldReturn201_AndSendConfirmationEmail()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var token = "CONFIRM_TOKEN_123";
            var request = new RegisterUserRequest(
                Email: "user@test.local",
                Password: "P@ssw0rd!",
                NomeCompleto: "Test User",
                DataDeNascimento: DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-20))
            );

            _uow.Setup(x => x.BeginAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
            _uow.Setup(x => x.CommitAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

            _users.Setup(x => x.EmailExistsAsync(request.Email, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(false);
            _users.Setup(x => x.CreateUserAsync(request.Email, request.Password, request.NomeCompleto, request.DataDeNascimento, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(userId);
            _users.Setup(x => x.EnsureRoleExistsAsync("User", It.IsAny<CancellationToken>()))
                  .Returns(Task.CompletedTask);
            _users.Setup(x => x.AddToRoleAsync(userId, "User", It.IsAny<CancellationToken>()))
                  .Returns(Task.CompletedTask);
            _users.Setup(x => x.GenerateEmailConfirmationTokenAsync(userId, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(token);

            string? capturedLink = null;
            _emails.Setup(x => x.SendEmailConfirmationAsync(
                    request.Email,
                    It.IsAny<string>(),
                    request.NomeCompleto,
                    It.IsAny<CancellationToken>()))
                   .Callback<string, string, string?, CancellationToken>((_, link, _, _) => capturedLink = link)
                   .Returns(Task.CompletedTask);

            var controller = CreateController();

            // Act
            var result = await controller.Register(request, Ct);

            // Assert
            result.Should().BeOfType<CreatedResult>();
            var created = (CreatedResult)result;
            created.StatusCode.Should().Be(StatusCodes.Status201Created);
            created.Value.Should().BeEquivalentTo(new { userId });

            capturedLink.Should().NotBeNullOrWhiteSpace();
            capturedLink.Should().Contain("/api/v1/auth/confirm-email");
            capturedLink.Should().Contain(userId.ToString());
            capturedLink.Should().Contain(WebUtility.UrlEncode(token));

            _emails.Verify(x => x.SendEmailConfirmationAsync(request.Email,
                It.IsAny<string>(), request.NomeCompleto, It.IsAny<CancellationToken>()),
                Times.Once);

            _uow.Verify(x => x.CommitAsync(It.IsAny<CancellationToken>()), Times.Once);
            _uow.Verify(x => x.RollbackAsync(It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Register_WhenEmailAlreadyExists_ShouldThrowAndRollback()
        {
            // Arrange
            var request = new RegisterUserRequest(
                Email: "user@test.local",
                Password: "P@ssw0rd!",
                NomeCompleto: "Test User",
                DataDeNascimento: DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-20))
            );

            _uow.Setup(x => x.BeginAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
            _uow.Setup(x => x.RollbackAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

            _users.Setup(x => x.EmailExistsAsync(request.Email, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(true);

            var controller = CreateController();

            // Act
            var act = async () => await controller.Register(request, Ct);

            // Assert
            await act.Should().ThrowAsync<InvalidOperationException>();

            _uow.Verify(x => x.RollbackAsync(It.IsAny<CancellationToken>()), Times.Once);
            _emails.Verify(x => x.SendEmailConfirmationAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            _uow.Verify(x => x.CommitAsync(It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Register_WhenUnexpectedException_ShouldThrowAndRollback_NoEmailSent()
        {
            // Arrange
            var request = new RegisterUserRequest(
                Email: "user@test.local",
                Password: "P@ssw0rd!",
                NomeCompleto: "Test User",
                DataDeNascimento: DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-20))
            );

            _uow.Setup(x => x.BeginAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
            _uow.Setup(x => x.RollbackAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

            _users.Setup(x => x.EmailExistsAsync(request.Email, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(false);
            _users.Setup(x => x.CreateUserAsync(request.Email, request.Password, request.NomeCompleto, request.DataDeNascimento, It.IsAny<CancellationToken>()))
                  .ThrowsAsync(new Exception("boom"));

            var controller = CreateController();

            // Act
            var act = async () => await controller.Register(request, Ct);

            // Assert
            await act.Should().ThrowAsync<Exception>().WithMessage("boom");

            _uow.Verify(x => x.RollbackAsync(It.IsAny<CancellationToken>()), Times.Once);
            _emails.Verify(x => x.SendEmailConfirmationAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            _uow.Verify(x => x.CommitAsync(It.IsAny<CancellationToken>()), Times.Never);
        }

        // POST /auth/confirm-email

        [Fact]
        public async Task ConfirmEmail_ShouldReturn200_OnSuccess()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var request = new ConfirmEmailRequest(userId.ToString(), "TOKEN");
            _users.Setup(x => x.ConfirmEmailAsync(userId, request.Token, It.IsAny<CancellationToken>()))
                  .Returns(Task.CompletedTask);

            var controller = CreateController();

            // Act
            var result = await controller.ConfirmEmail(request, Ct);

            // Assert
            result.Should().BeOfType<OkObjectResult>();
            _users.Verify(x => x.ConfirmEmailAsync(userId, request.Token, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task ConfirmEmail_ShouldReturn400_WhenUserIdIsInvalid()
        {
            // Arrange
            var request = new ConfirmEmailRequest("INVALID_GUID", "TOKEN");
            var controller = CreateController();

            // Act
            var result = await controller.ConfirmEmail(request, Ct);

            // Assert
            result.Should().BeOfType<BadRequestObjectResult>();
            var bad = (BadRequestObjectResult)result;
            var problem = bad.Value.Should().BeOfType<ProblemDetails>().Subject;
            problem.Title.Should().Be("Invalid userId");
        }

        [Fact]
        public async Task ConfirmEmail_ShouldThrow_WhenUserNotFound()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var request = new ConfirmEmailRequest(userId.ToString(), "TOKEN");

            _users.Setup(x => x.ConfirmEmailAsync(userId, request.Token, It.IsAny<CancellationToken>()))
                  .ThrowsAsync(new KeyNotFoundException("Usuário não encontrado"));

            var controller = CreateController();

            // Act
            var act = async () => await controller.ConfirmEmail(request, Ct);

            // Assert
            await act.Should().ThrowAsync<KeyNotFoundException>()
                .WithMessage("*Usuário não encontrado*");
        }

        // POST /auth/login

        [Fact]
        public async Task Login_ShouldReturn200_AndAuthResponse_OnSuccess()
        {
            // Arrange
            var request = new LoginRequest("user@test.local", "P@ssw0rd!");
            var userId = Guid.NewGuid();
            var roles = new List<string> { "User" };

            var access = new AccessTokenResult("jwt-access", DateTimeOffset.UtcNow.AddMinutes(30),
                new Dictionary<string, string> { { "UserID", userId.ToString() } });

            var refreshEntity = new RefreshToken(userId, "hash", "salt", DateTimeOffset.UtcNow.AddDays(7), "127.0.0.1");
            var refresh = new RefreshTokenResult(refreshEntity, "rt.plain", refreshEntity.ExpiresAt);

            _users.Setup(x => x.GetUserIdByEmailAsync(request.Email, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(userId);
            _users.Setup(x => x.CheckPasswordAsync(userId, request.Password, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(true);
            _users.Setup(x => x.IsEmailConfirmedAsync(userId, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(true);
            _users.Setup(x => x.GetRolesAsync(userId, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(roles);
            _users.Setup(x => x.AddRefreshTokenAsync(refreshEntity, It.IsAny<CancellationToken>()))
                  .Returns(Task.CompletedTask);

            _tokens.Setup(x => x.GenerateAccessToken(userId, request.Email, roles, It.IsAny<IDictionary<string, string>?>()))
                   .Returns(access);
            _tokens.Setup(x => x.CreateRefreshToken(userId, It.IsAny<string?>(), It.IsAny<TimeSpan?>()))
                   .Returns(refresh);

            var controller = CreateController(ip: "127.0.0.1");

            // Act
            var result = await controller.Login(request, Ct);

            // Assert
            result.Should().BeOfType<OkObjectResult>();
            var ok = (OkObjectResult)result;
            ok.Value.Should().BeOfType<AuthResponse>()
                .Which.Should().BeEquivalentTo(new
                {
                    AccessToken = access.Token,
                    ExpiresAt = access.ExpiresAt,
                    RefreshToken = refresh.PlainText,
                    RefreshTokenExpiresAt = refresh.ExpiresAt
                });
        }

        [Fact]
        public async Task Login_ShouldThrow_WhenCredentialsInvalid()
        {
            // Arrange
            var request = new LoginRequest("user@test.local", "bad");
            _users.Setup(x => x.GetUserIdByEmailAsync(request.Email, It.IsAny<CancellationToken>()))
                  .ReturnsAsync((Guid?)null);

            var controller = CreateController();

            // Act
            var act = async () => await controller.Login(request, Ct);

            // Assert
            await act.Should().ThrowAsync<InvalidOperationException>();
        }

        [Fact]
        public async Task Login_ShouldThrow_WhenEmailNotConfirmed()
        {
            // Arrange
            var request = new LoginRequest("user@test.local", "P@ssw0rd!");
            var userId = Guid.NewGuid();

            _users.Setup(x => x.GetUserIdByEmailAsync(request.Email, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(userId);
            _users.Setup(x => x.CheckPasswordAsync(userId, request.Password, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(true);
            _users.Setup(x => x.IsEmailConfirmedAsync(userId, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(false);

            var controller = CreateController();

            // Act
            var act = async () => await controller.Login(request, Ct);

            // Assert
            await act.Should().ThrowAsync<InvalidOperationException>();
        }

        // POST /auth/refresh-token

        [Fact]
        public async Task RefreshToken_ShouldReturn200_AndRotate_OnValidToken()
        {
            // Arrange
            var tokenId = Guid.NewGuid();
            var userId = Guid.NewGuid();
            var plainRequest = $"{tokenId}.payload";

            var entity = new RefreshToken(userId, "hash", "salt", DateTimeOffset.UtcNow.AddDays(7), "127.0.0.1");
            var access = new AccessTokenResult("access.jwt", DateTimeOffset.UtcNow.AddMinutes(15),
                new Dictionary<string, string>());
            var newRtEntity = new RefreshToken(userId, "hash2", "salt2", DateTimeOffset.UtcNow.AddDays(7), "127.0.0.1");
            var newRt = new RefreshTokenResult(newRtEntity, "new.rt.plain", newRtEntity.ExpiresAt);
            var roles = new List<string> { "User" };

            _users.Setup(x => x.GetRefreshTokenAsync(tokenId, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(entity);
            _tokens.Setup(x => x.ValidateRefreshToken(plainRequest, entity)).Returns(true);
            _users.Setup(x => x.GetEmailByUserIdAsync(entity.UserId, It.IsAny<CancellationToken>()))
                  .ReturnsAsync("user@test.local");
            _users.Setup(x => x.GetRolesAsync(entity.UserId, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(roles);

            _tokens.Setup(x => x.GenerateAccessToken(entity.UserId, "user@test.local", roles, It.IsAny<IDictionary<string, string>?>()))
                   .Returns(access);
            _tokens.Setup(x => x.CreateRefreshToken(entity.UserId, It.IsAny<string?>(), It.IsAny<TimeSpan?>()))
                   .Returns(newRt);

            _users.Setup(x => x.UpdateRefreshTokenAsync(It.IsAny<RefreshToken>(), It.IsAny<CancellationToken>()))
                  .Returns(Task.CompletedTask);
            _users.Setup(x => x.AddRefreshTokenAsync(newRtEntity, It.IsAny<CancellationToken>()))
                  .Returns(Task.CompletedTask);

            var controller = CreateController(ip: "127.0.0.1");
            var request = new RefreshTokenRequest(plainRequest);

            // Act
            var result = await controller.RefreshToken(request, Ct);

            // Assert
            result.Should().BeOfType<OkObjectResult>();
            var ok = (OkObjectResult)result;
            ok.Value.Should().BeOfType<AuthResponse>()
                .Which.Should().BeEquivalentTo(new
                {
                    AccessToken = access.Token,
                    access.ExpiresAt,
                    RefreshToken = newRt.PlainText,
                    RefreshTokenExpiresAt = newRt.ExpiresAt
                });

            _users.Verify(x => x.UpdateRefreshTokenAsync(It.IsAny<RefreshToken>(), It.IsAny<CancellationToken>()), Times.Once);
            _users.Verify(x => x.AddRefreshTokenAsync(newRtEntity, It.IsAny<CancellationToken>()), Times.Once);
            _users.Verify(x => x.RevokeTokenCascadeAsync(It.IsAny<RefreshToken>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task RefreshToken_ShouldReturn401_WhenEmpty()
        {
            var controller = CreateController();
            var result = await controller.RefreshToken(new RefreshTokenRequest(""), Ct);

            result.Should().BeOfType<UnauthorizedObjectResult>();
            var unauthorized = (UnauthorizedObjectResult)result;
            var problem = unauthorized.Value.Should().BeOfType<ProblemDetails>().Subject;
            problem.Title.Should().Be("Invalid refresh token");
        }

        [Fact]
        public async Task RefreshToken_ShouldReturn401_WhenFormatInvalid()
        {
            var controller = CreateController();
            var result = await controller.RefreshToken(new RefreshTokenRequest("invalid_format_without_dot"), Ct);

            result.Should().BeOfType<UnauthorizedObjectResult>();
            var problem = ((UnauthorizedObjectResult)result).Value.Should().BeOfType<ProblemDetails>().Subject;
            problem.Title.Should().Be("Invalid refresh token format");
        }

        [Fact]
        public async Task RefreshToken_ShouldReturn401_WhenNotFound()
        {
            var tokenId = Guid.NewGuid();
            var request = new RefreshTokenRequest($"{tokenId}.payload");

            _users.Setup(x => x.GetRefreshTokenAsync(tokenId, It.IsAny<CancellationToken>()))
                  .ReturnsAsync((RefreshToken?)null);

            var controller = CreateController();
            var result = await controller.RefreshToken(request, Ct);

            result.Should().BeOfType<UnauthorizedObjectResult>();
            var problem = ((UnauthorizedObjectResult)result).Value.Should().BeOfType<ProblemDetails>().Subject;
            problem.Title.Should().Be("Refresh token not found");
        }

        [Fact]
        public async Task RefreshToken_ShouldReturn401_AndRevokeCascade_WhenInvalidSignature()
        {
            var tokenId = Guid.NewGuid();
            var userId = Guid.NewGuid();
            var plainRequest = $"{tokenId}.payload";
            var entity = new RefreshToken(userId, "hash", "salt", DateTimeOffset.UtcNow.AddDays(7), "127.0.0.1");

            _users.Setup(x => x.GetRefreshTokenAsync(tokenId, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(entity);
            _tokens.Setup(x => x.ValidateRefreshToken(plainRequest, entity))
                   .Returns(false);

            _users.Setup(x => x.RevokeTokenCascadeAsync(entity, "Invalid refresh attempt", It.IsAny<string?>(), It.IsAny<CancellationToken>()))
                  .Returns(Task.CompletedTask);

            var controller = CreateController(ip: "127.0.0.1");
            var result = await controller.RefreshToken(new RefreshTokenRequest(plainRequest), Ct);

            result.Should().BeOfType<UnauthorizedObjectResult>();
            var problem = ((UnauthorizedObjectResult)result).Value.Should().BeOfType<ProblemDetails>().Subject;
            problem.Title.Should().Be("Invalid refresh token");

            _users.Verify(x => x.RevokeTokenCascadeAsync(entity, "Invalid refresh attempt", It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Once);
        }

        // POST /auth/forgot-password

        [Fact]
        public async Task ForgotPassword_ShouldReturn200_AndSendEmail_WhenUserExists()
        {
            var email = "user@test.local";
            var userId = Guid.NewGuid();
            var resetToken = "RESET_TOKEN";

            _users.Setup(x => x.GetUserIdByEmailAsync(email, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(userId);
            _users.Setup(x => x.GeneratePasswordResetTokenAsync(userId, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(resetToken);

            string? captured = null;
            _emails.Setup(x => x.SendPasswordResetAsync(email, It.IsAny<string>(), null, It.IsAny<CancellationToken>()))
                   .Callback<string, string, string?, CancellationToken>((_, link, _, _) => captured = link)
                   .Returns(Task.CompletedTask);

            var controller = CreateController();
            var result = await controller.ForgotPassword(new ForgotPasswordRequest(email), Ct);

            result.Should().BeOfType<OkObjectResult>();
            captured.Should().NotBeNullOrWhiteSpace();
            captured.Should().Contain("/api/v1/auth/reset-password");
            captured.Should().Contain(userId.ToString());
            captured.Should().Contain(WebUtility.UrlEncode(resetToken));

            _emails.Verify(x => x.SendPasswordResetAsync(email, It.IsAny<string>(), null, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task ForgotPassword_ShouldReturn200_AndNotSendEmail_WhenUserDoesNotExist()
        {
            var email = "absent@test.local";
            _users.Setup(x => x.GetUserIdByEmailAsync(email, It.IsAny<CancellationToken>()))
                  .ReturnsAsync((Guid?)null);

            var controller = CreateController();
            var result = await controller.ForgotPassword(new ForgotPasswordRequest(email), Ct);

            result.Should().BeOfType<OkObjectResult>();
            _emails.Verify(x => x.SendPasswordResetAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task ForgotPassword_ShouldReturn200_EvenWithEmptyEmail()
        {
            var controller = CreateController();
            var result = await controller.ForgotPassword(new ForgotPasswordRequest(""), Ct);

            result.Should().BeOfType<OkObjectResult>();
        }

        // POST /auth/reset-password

        [Fact]
        public async Task ResetPassword_ShouldReturn200_OnSuccess()
        {
            var userId = Guid.NewGuid();
            var request = new ResetPasswordRequest(userId.ToString(), "TOKEN", "NewP@ss!");

            _users.Setup(x => x.ResetPasswordAsync(userId, request.Token, request.NewPassword, It.IsAny<CancellationToken>()))
                  .Returns(Task.CompletedTask);

            var controller = CreateController();
            var result = await controller.ResetPassword(request, Ct);

            result.Should().BeOfType<OkObjectResult>();
            _users.Verify(x => x.ResetPasswordAsync(userId, request.Token, request.NewPassword, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task ResetPassword_ShouldReturn400_WhenUserIdInvalid()
        {
            var request = new ResetPasswordRequest("INVALID", "TOKEN", "NewP@ss!");
            var controller = CreateController();

            var result = await controller.ResetPassword(request, Ct);

            result.Should().BeOfType<BadRequestObjectResult>();
            var problem = ((BadRequestObjectResult)result).Value.Should().BeOfType<ProblemDetails>().Subject;
            problem.Title.Should().Be("Invalid userId");
        }

        // POST /auth/logout

        [Fact]
        public async Task Logout_ShouldReturn200_AndRevoke_WhenValidTokenProvided()
        {
            var tokenId = Guid.NewGuid();
            var plain = $"{tokenId}.payload";
            var entity = new RefreshToken(Guid.NewGuid(), "h", "s", DateTimeOffset.UtcNow.AddDays(7), "127.0.0.1");

            _users.Setup(x => x.GetRefreshTokenAsync(tokenId, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(entity);
            _users.Setup(x => x.RevokeTokenCascadeAsync(entity, "Logout", It.IsAny<string?>(), It.IsAny<CancellationToken>()))
                  .Returns(Task.CompletedTask);

            var controller = CreateController(ip: "127.0.0.1");
            var result = await controller.Logout(new RefreshTokenRequest(plain), Ct);

            result.Should().BeOfType<OkObjectResult>();
            _users.Verify(x => x.RevokeTokenCascadeAsync(entity, "Logout", It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Logout_ShouldReturn200_WhenTokenEmptyOrInvalid()
        {
            var controller = CreateController();

            var r1 = await controller.Logout(new RefreshTokenRequest(""), Ct);
            r1.Should().BeOfType<OkResult>();

            var r2 = await controller.Logout(new RefreshTokenRequest("invalid_format"), Ct);
            r2.Should().BeOfType<OkObjectResult>();

            _users.Verify(x => x.RevokeTokenCascadeAsync(It.IsAny<RefreshToken>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }
}