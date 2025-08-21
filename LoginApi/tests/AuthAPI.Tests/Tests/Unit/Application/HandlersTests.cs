using AuthAPI.Application.Handlers;
using AuthAPI.Application.Interfaces;
using AuthAPI.Domain.Entities;
using AuthAPI.Tests.Tests.Shared;
using FluentAssertions;
using Moq;

namespace AuthAPI.Tests.Tests.Unit.Application
{
    public class HandlersTests(TestFixture fixture) : TestBase(fixture), IClassFixture<TestFixture>
    {
        // RegisterUserCommandHandler
        [Fact]
        public async Task RegisterUserCommandHandler_Success_ShouldCreateUser_AddRole_GenerateToken_AndCommit()
        {
            var users = new Mock<IUserRepository>(MockBehavior.Strict);
            var uow = new Mock<IUnitOfWork>(MockBehavior.Strict);

            var userId = Guid.NewGuid();
            var confirmToken = "CONFIRM_TOKEN_X";

            uow.Setup(x => x.BeginAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
            uow.Setup(x => x.CommitAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
            uow.Setup(x => x.RollbackAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

            users.Setup(x => x.EmailExistsAsync("user@test.local", It.IsAny<CancellationToken>())).ReturnsAsync(false);
            users.Setup(x => x.CreateUserAsync("user@test.local", "Abcdef12", "Nome Completo", It.IsAny<DateOnly?>(), It.IsAny<CancellationToken>()))
                 .ReturnsAsync(userId);
            users.Setup(x => x.EnsureRoleExistsAsync("User", It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
            users.Setup(x => x.AddToRoleAsync(userId, "User", It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
            users.Setup(x => x.GenerateEmailConfirmationTokenAsync(userId, It.IsAny<CancellationToken>()))
                 .ReturnsAsync(confirmToken);

            var handler = new RegisterUserCommandHandler(users.Object, uow.Object);
            var cmd = new RegisterUserCommand("user@test.local", "Abcdef12", "Nome Completo", DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-20)));

            var result = await handler.Handle(cmd, Ct);

            result.UserId.Should().Be(userId);
            result.EmailConfirmationToken.Should().Be(confirmToken);

            uow.Verify(x => x.BeginAsync(It.IsAny<CancellationToken>()), Times.Once);
            users.Verify(x => x.EnsureRoleExistsAsync("User", It.IsAny<CancellationToken>()), Times.Once);
            users.Verify(x => x.AddToRoleAsync(userId, "User", It.IsAny<CancellationToken>()), Times.Once);
            users.Verify(x => x.GenerateEmailConfirmationTokenAsync(userId, It.IsAny<CancellationToken>()), Times.Once);
            uow.Verify(x => x.CommitAsync(It.IsAny<CancellationToken>()), Times.Once);
            uow.Verify(x => x.RollbackAsync(It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task RegisterUserCommandHandler_WhenEmailExists_ShouldThrowAndRollback()
        {
            var users = new Mock<IUserRepository>();
            var uow = new Mock<IUnitOfWork>();

            uow.Setup(x => x.BeginAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
            uow.Setup(x => x.RollbackAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

            users.Setup(x => x.EmailExistsAsync("exist@test.local", It.IsAny<CancellationToken>())).ReturnsAsync(true);

            var handler = new RegisterUserCommandHandler(users.Object, uow.Object);
            var cmd = new RegisterUserCommand("exist@test.local", "Abcdef12", "Nome", DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-30)));

            var act = async () => await handler.Handle(cmd, Ct);

            await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*Email já cadastrado*");
            uow.Verify(x => x.RollbackAsync(It.IsAny<CancellationToken>()), Times.Once);
            uow.Verify(x => x.CommitAsync(It.IsAny<CancellationToken>()), Times.Never);
            users.Verify(x => x.CreateUserAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DateOnly?>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task RegisterUserCommandHandler_WhenCreateUserThrows_ShouldRollback_AndPropagate()
        {
            var users = new Mock<IUserRepository>();
            var uow = new Mock<IUnitOfWork>();

            uow.Setup(x => x.BeginAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
            uow.Setup(x => x.RollbackAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

            users.Setup(x => x.EmailExistsAsync("user@test.local", It.IsAny<CancellationToken>())).ReturnsAsync(false);
            users.Setup(x => x.CreateUserAsync("user@test.local", "Abcdef12", "Nome", It.IsAny<DateOnly?>(), It.IsAny<CancellationToken>()))
                 .ThrowsAsync(new Exception("boom"));

            var handler = new RegisterUserCommandHandler(users.Object, uow.Object);
            var cmd = new RegisterUserCommand("user@test.local", "Abcdef12", "Nome", DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-22)));

            var act = async () => await handler.Handle(cmd, Ct);

            await act.Should().ThrowAsync<Exception>().WithMessage("boom");
            uow.Verify(x => x.RollbackAsync(It.IsAny<CancellationToken>()), Times.Once);
            uow.Verify(x => x.CommitAsync(It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task RegisterUserCommandHandler_WhenCommitThrows_ShouldRollback()
        {
            var users = new Mock<IUserRepository>();
            var uow = new Mock<IUnitOfWork>();

            var userId = Guid.NewGuid();

            uow.Setup(x => x.BeginAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
            uow.Setup(x => x.CommitAsync(It.IsAny<CancellationToken>())).ThrowsAsync(new Exception("commit failed"));
            uow.Setup(x => x.RollbackAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

            users.Setup(x => x.EmailExistsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(false);
            users.Setup(x => x.CreateUserAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DateOnly?>(), It.IsAny<CancellationToken>()))
                 .ReturnsAsync(userId);
            users.Setup(x => x.EnsureRoleExistsAsync("User", It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
            users.Setup(x => x.AddToRoleAsync(userId, "User", It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
            users.Setup(x => x.GenerateEmailConfirmationTokenAsync(userId, It.IsAny<CancellationToken>()))
                 .ReturnsAsync("TOKEN");

            var handler = new RegisterUserCommandHandler(users.Object, uow.Object);
            var cmd = new RegisterUserCommand("u@test.local", "Abcdef12", "Nome", DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-29)));

            var act = async () => await handler.Handle(cmd, Ct);

            await act.Should().ThrowAsync<Exception>().WithMessage("commit failed");
            uow.Verify(x => x.RollbackAsync(It.IsAny<CancellationToken>()), Times.Once);
        }

        // LoginQueryHandler
        [Fact]
        public async Task LoginQueryHandler_Success_ShouldReturnAuthResponse_AndPersistRefreshToken()
        {
            var users = new Mock<IUserRepository>();
            var tokens = new Mock<ITokenService>();

            var userId = Guid.NewGuid();
            var email = "user@test.local";
            var roles = new List<string> { "User" };

            var access = new AccessTokenResult("access.jwt", DateTimeOffset.UtcNow.AddMinutes(30), new Dictionary<string, string>());
            var rtEntity = new RefreshToken(userId, "hash", "salt", DateTimeOffset.UtcNow.AddDays(7), "127.0.0.1");
            var refresh = new RefreshTokenResult(rtEntity, "rt.plain", rtEntity.ExpiresAt);

            users.Setup(x => x.GetUserIdByEmailAsync(email, It.IsAny<CancellationToken>())).ReturnsAsync(userId);
            users.Setup(x => x.CheckPasswordAsync(userId, "Abcdef12", It.IsAny<CancellationToken>())).ReturnsAsync(true);
            users.Setup(x => x.IsEmailConfirmedAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(true);
            users.Setup(x => x.GetRolesAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(roles);
            users.Setup(x => x.AddRefreshTokenAsync(rtEntity, It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

            tokens.Setup(x => x.GenerateAccessToken(userId, email, roles, It.IsAny<IDictionary<string, string>?>()))
                  .Returns(access);
            tokens.Setup(x => x.CreateRefreshToken(userId, "127.0.0.1", It.IsAny<TimeSpan?>()))
                  .Returns(refresh);

            var handler = new LoginQueryHandler(users.Object, tokens.Object);
            var query = new LoginQuery(email, "Abcdef12", "127.0.0.1");

            var result = await handler.Handle(query, Ct);

            result.Response.AccessToken.Should().Be(access.Token);
            result.Response.ExpiresAt.Should().Be(access.ExpiresAt);
            result.Response.RefreshToken.Should().Be(refresh.PlainText);
            result.Response.RefreshTokenExpiresAt.Should().Be(refresh.ExpiresAt);

            tokens.Verify(x => x.CreateRefreshToken(userId, "127.0.0.1", It.IsAny<TimeSpan?>()), Times.Once);
            users.Verify(x => x.AddRefreshTokenAsync(rtEntity, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task LoginQueryHandler_ShouldThrow_WhenEmailNotFound()
        {
            var users = new Mock<IUserRepository>();
            var tokens = new Mock<ITokenService>();

            users.Setup(x => x.GetUserIdByEmailAsync("absent@test.local", It.IsAny<CancellationToken>())).ReturnsAsync((Guid?)null);

            var handler = new LoginQueryHandler(users.Object, tokens.Object);
            var query = new LoginQuery("absent@test.local", "pwd", "1.1.1.1");

            var act = async () => await handler.Handle(query, Ct);

            await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*Credenciais inválidas*");
        }

        [Fact]
        public async Task LoginQueryHandler_ShouldThrow_WhenPasswordInvalid()
        {
            var users = new Mock<IUserRepository>();
            var tokens = new Mock<ITokenService>();

            var userId = Guid.NewGuid();
            users.Setup(x => x.GetUserIdByEmailAsync("user@test.local", It.IsAny<CancellationToken>())).ReturnsAsync(userId);
            users.Setup(x => x.CheckPasswordAsync(userId, "wrong", It.IsAny<CancellationToken>())).ReturnsAsync(false);

            var handler = new LoginQueryHandler(users.Object, tokens.Object);
            var query = new LoginQuery("user@test.local", "wrong", "1.1.1.1");

            var act = async () => await handler.Handle(query, Ct);

            await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*Credenciais inválidas*");
        }

        [Fact]
        public async Task LoginQueryHandler_ShouldThrow_WhenEmailNotConfirmed()
        {
            var users = new Mock<IUserRepository>();
            var tokens = new Mock<ITokenService>();

            var userId = Guid.NewGuid();
            users.Setup(x => x.GetUserIdByEmailAsync("user@test.local", It.IsAny<CancellationToken>())).ReturnsAsync(userId);
            users.Setup(x => x.CheckPasswordAsync(userId, "Abcdef12", It.IsAny<CancellationToken>())).ReturnsAsync(true);
            users.Setup(x => x.IsEmailConfirmedAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(false);

            var handler = new LoginQueryHandler(users.Object, tokens.Object);
            var query = new LoginQuery("user@test.local", "Abcdef12", "10.0.0.2");

            var act = async () => await handler.Handle(query, Ct);

            await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*Email não confirmado*");
        }
    }
}