using System.Reflection;
using System.Security.Claims;
using AuthAPI.API.Controllers;
using AuthAPI.Tests.Tests.Shared;
using FluentAssertions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthAPI.Tests.Tests.Unit.Controllers
{
    public class AdminControllerTests(TestFixture fixture) : TestBase(fixture), IClassFixture<TestFixture>
    {
        private static AdminController CreateControllerWithPrincipal(params Claim[] claims)
        {
            var http = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"))
            };

            var controller = new AdminController
            {
                ControllerContext = new ControllerContext { HttpContext = http }
            };
            return controller;
        }

        [Fact]
        public void Controller_ShouldHaveAuthorizeAttribute_WithAdminRole()
        {
            // Arrange
            var type = typeof(AdminController);

            // Act
            var authorize = type.GetCustomAttribute<AuthorizeAttribute>(inherit: true);

            // Assert
            authorize.Should().NotBeNull();
            authorize!.Roles.Should().NotBeNullOrWhiteSpace();
            authorize.Roles!.Split(',').Select(r => r.Trim()).Should().Contain("Admin");
        }

        [Fact]
        public void Dashboard_ShouldReturn200_ForAdminRole()
        {
            // Arrange
            var controller = CreateControllerWithPrincipal(new Claim(ClaimTypes.Role, "Admin"));

            // Act
            var result = controller.Dashboard();

            // Assert
            result.Should().BeOfType<OkObjectResult>();
            var ok = (OkObjectResult)result;
            ok.Value.Should().NotBeNull();
            ok.Value.Should().BeEquivalentTo(new
            {
                message = "Admin dashboard OK",
                serverTimeUtc = default(DateTimeOffset)
            }, opts => opts.Excluding(x => x.serverTimeUtc)); // ignorar valor dinâmico do tempo
        }
    }
}