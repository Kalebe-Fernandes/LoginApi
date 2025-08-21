using System.Security.Claims;
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
    public class UsersControllerTests : TestBase, IClassFixture<TestFixture>
    {
        private readonly Mock<IUnitOfWork> _uow = new();
        private readonly Mock<IUserRepository> _users = new();

        public UsersControllerTests(TestFixture fixture) : base(fixture)
        {
            _uow.SetupGet(x => x.Users).Returns(_users.Object);
        }

        private UsersController CreateControllerWithUser(Guid? userId, bool useNameIdentifier = false)
        {
            var http = new DefaultHttpContext();

            if (userId.HasValue)
            {
                var claimType = useNameIdentifier ? ClaimTypes.NameIdentifier : "UserID";
                var identity = new ClaimsIdentity([new Claim(claimType, userId.Value.ToString())], "Test");
                http.User = new ClaimsPrincipal(identity);
            }
            else
            {
                http.User = new ClaimsPrincipal(new ClaimsIdentity()); // no claims
            }

            var controller = new UsersController(_uow.Object)
            {
                ControllerContext = new ControllerContext { HttpContext = http }
            };

            return controller;
        }

        [Fact]
        public async Task Me_ShouldReturn200_WithUserMeResponse()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var email = "user@test.local";
            var profile = new UserProfile(userId, "Test User", DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-25)));
            var roles = new List<string> { "User", "Viewer" };

            _users.Setup(x => x.GetEmailByUserIdAsync(userId, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(email);
            _users.Setup(x => x.GetProfileAsync(userId, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(profile);
            _users.Setup(x => x.GetRolesAsync(userId, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(roles);

            var controller = CreateControllerWithUser(userId);

            // Act
            var result = await controller.Me(Ct);

            // Assert
            result.Should().BeOfType<OkObjectResult>();
            var ok = (OkObjectResult)result;
            ok.Value.Should().BeOfType<UserMeResponse>()
                .Which.Should().BeEquivalentTo(new
                {
                    UserId = userId,
                    Email = email,
                    profile.NomeCompleto,
                    profile.DataDeNascimento,
                    Roles = roles
                });
        }

        [Fact]
        public async Task Me_ShouldReturn401_WhenClaimsMissing()
        {
            // Arrange
            var controller = CreateControllerWithUser(null);

            // Act
            var result = await controller.Me(Ct);

            // Assert
            result.Should().BeOfType<UnauthorizedObjectResult>();
            var problem = ((UnauthorizedObjectResult)result).Value.Should().BeOfType<ProblemDetails>().Subject;
            problem.Title.Should().Be("Invalid token claims");
        }

        [Fact]
        public async Task Me_ShouldReturn401_WhenClaimIsInvalidGuid()
        {
            // Arrange - inject invalid GUID value
            var http = new DefaultHttpContext();
            var identity = new ClaimsIdentity(new[] { new Claim("UserID", "NOT-A-GUID") }, "Test");
            http.User = new ClaimsPrincipal(identity);

            var controller = new UsersController(_uow.Object)
            {
                ControllerContext = new ControllerContext { HttpContext = http }
            };

            // Act
            var result = await controller.Me(Ct);

            // Assert
            result.Should().BeOfType<UnauthorizedObjectResult>();
            var problem = ((UnauthorizedObjectResult)result).Value.Should().BeOfType<ProblemDetails>().Subject;
            problem.Title.Should().Be("Invalid token claims");
        }

        [Fact]
        public async Task Me_ShouldThrow_NotFound_WhenRepositoryThrowsKeyNotFound()
        {
            // Arrange
            var userId = Guid.NewGuid();

            _users.Setup(x => x.GetEmailByUserIdAsync(userId, It.IsAny<CancellationToken>()))
                  .ThrowsAsync(new KeyNotFoundException("Usuário não encontrado"));

            var controller = CreateControllerWithUser(userId);

            // Act
            var act = async () => await controller.Me(Ct);

            // Assert
            await act.Should().ThrowAsync<KeyNotFoundException>()
                .WithMessage("*Usuário não encontrado*");
        }

        [Fact]
        public async Task Me_ShouldReturn200_AlsoWhenClaimNameIdentifierIsUsed()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var email = "user.claims@test.local";
            var profile = new UserProfile(userId, "Name Id User", null);
            var roles = new List<string> { "User" };

            _users.Setup(x => x.GetEmailByUserIdAsync(userId, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(email);
            _users.Setup(x => x.GetProfileAsync(userId, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(profile);
            _users.Setup(x => x.GetRolesAsync(userId, It.IsAny<CancellationToken>()))
                  .ReturnsAsync(roles);

            var controller = CreateControllerWithUser(userId, useNameIdentifier: true);

            // Act
            var result = await controller.Me(Ct);

            // Assert
            result.Should().BeOfType<OkObjectResult>();
            var ok = (OkObjectResult)result;
            ok.Value.Should().BeOfType<UserMeResponse>();
        }
    }
}