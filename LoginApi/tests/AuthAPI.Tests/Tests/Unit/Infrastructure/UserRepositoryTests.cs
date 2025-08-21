using System.Reflection;
using AuthAPI.Domain.Entities;
using AuthAPI.Infrastructure.Identity;
using AuthAPI.Infrastructure.Repositories;
using AuthAPI.Tests.Tests.Shared;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Moq;

namespace AuthAPI.Tests.Tests.Unit.Infrastructure
{
    public class UserRepositoryTests(TestFixture fixture) : TestBase(fixture), IClassFixture<TestFixture>
    {
        private static Mock<UserManager<ApplicationUser>> CreateUserManagerMock()
        {
            var store = new Mock<IUserStore<ApplicationUser>>();
            return new Mock<UserManager<ApplicationUser>>(
                store.Object,
                null!, null!, null!, null!, null!, null!, null!, null!
            );
        }

        private static Mock<RoleManager<ApplicationRole>> CreateRoleManagerMock()
        {
            var roleStore = new Mock<IRoleStore<ApplicationRole>>();
            var validators = new List<IRoleValidator<ApplicationRole>>();
            return new Mock<RoleManager<ApplicationRole>>(
                roleStore.Object,
                validators,
                new UpperInvariantLookupNormalizer(),
                new IdentityErrorDescriber(),
                null!
            );
        }

        private static void SetPrivate<T, TValue>(T obj, string prop, TValue value)
        {
            var pi = typeof(T).GetProperty(prop, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            pi!.SetValue(obj, value);
        }

        private static RefreshToken NewToken(Guid userId, int minutesAhead = 60, string? ip = "127.0.0.1")
        {
            return new RefreshToken(userId, Convert.ToBase64String(Guid.NewGuid().ToByteArray()), Convert.ToBase64String(Guid.NewGuid().ToByteArray()), DateTimeOffset.UtcNow.AddMinutes(minutesAhead), ip);
        }

        [Fact]
        public async Task EmailExists_GetUserId_GetEmailById_ShouldWork()
        {
            var db = CreateInMemoryDbContext();
            var um = CreateUserManagerMock();
            var rm = CreateRoleManagerMock();

            var user = new ApplicationUser { Id = Guid.NewGuid(), Email = "user@test.local", UserName = "user@test.local", NomeCompleto = "User One" };

            um.Setup(x => x.FindByEmailAsync(user.Email!)).ReturnsAsync(user);
            um.Setup(x => x.FindByIdAsync(user.Id.ToString())).ReturnsAsync(user);

            var repo = new UserRepository(db, um.Object, rm.Object);

            (await repo.EmailExistsAsync(user.Email!, Ct)).Should().BeTrue();
            (await repo.GetUserIdByEmailAsync(user.Email!, Ct)).Should().Be(user.Id);
            (await repo.GetEmailByUserIdAsync(user.Id, Ct)).Should().Be(user.Email);
        }

        [Fact]
        public async Task CreateUserAsync_ShouldCreateIdentityUser_AndProfile_Success()
        {
            var db = CreateInMemoryDbContext();
            var um = CreateUserManagerMock();
            var rm = CreateRoleManagerMock();

            um.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
              .ReturnsAsync(IdentityResult.Success);

            var repo = new UserRepository(db, um.Object, rm.Object);

            var email = "new@test.local";
            var nome = "New User";
            var dob = DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-20));

            var id = await repo.CreateUserAsync(email, "P@ssw0rd!", nome, dob, Ct);

            id.Should().NotBe(Guid.Empty);

            var profile = await db.UserProfiles.FindAsync([id], Ct);
            profile.Should().NotBeNull();
            profile!.Id.Should().Be(id);
            profile.NomeCompleto.Should().Be(nome);
            profile.DataDeNascimento.Should().Be(dob);

            um.Verify(x => x.CreateAsync(It.Is<ApplicationUser>(u => u.Email == email && u.NomeCompleto == nome && u.DataDeNascimento == dob), "P@ssw0rd!"), Times.Once);
        }

        [Fact]
        public async Task CreateUserAsync_ShouldThrow_WithAggregatedIdentityErrors_DuplicateEmail()
        {
            var db = CreateInMemoryDbContext();
            var um = CreateUserManagerMock();
            var rm = CreateRoleManagerMock();

            var errors = new[]
            {
                new IdentityError { Code = "DuplicateEmail", Description = "Email already taken." }
            };

            um.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
              .ReturnsAsync(IdentityResult.Failed(errors));

            var repo = new UserRepository(db, um.Object, rm.Object);

            var act = async () => await repo.CreateUserAsync("dup@test.local", "P@ssw0rd!", "Dup", null, Ct);

            await act.Should().ThrowAsync<InvalidOperationException>()
               .WithMessage("*DuplicateEmail:Email already taken.*");
        }

        [Fact]
        public async Task CreateUserAsync_ShouldAggregateMultipleErrors()
        {
            var db = CreateInMemoryDbContext();
            var um = CreateUserManagerMock();
            var rm = CreateRoleManagerMock();

            var errors = new[]
            {
                new IdentityError { Code = "PwdTooShort", Description = "Password too short." },
                new IdentityError { Code = "PwdRequiresDigit", Description = "Password requires digit." }
            };

            um.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
              .ReturnsAsync(IdentityResult.Failed(errors));

            var repo = new UserRepository(db, um.Object, rm.Object);

            var act = async () => await repo.CreateUserAsync("x@test.local", "bad", "User", null, Ct);

            await act.Should().ThrowAsync<InvalidOperationException>()
               .WithMessage("*PwdTooShort:Password too short.*PwdRequiresDigit:Password requires digit.*");
        }

        [Fact]
        public async Task EnsureRoleExists_ShouldCreate_WhenMissing_AndThrowOnFailure()
        {
            var db = CreateInMemoryDbContext();
            var um = CreateUserManagerMock();
            var rm = CreateRoleManagerMock();

            rm.Setup(x => x.RoleExistsAsync("Manager")).ReturnsAsync(false);
            rm.Setup(x => x.CreateAsync(It.Is<ApplicationRole>(r => r.Name == "Manager")))
              .ReturnsAsync(IdentityResult.Success);

            var repo = new UserRepository(db, um.Object, rm.Object);
            await repo.EnsureRoleExistsAsync("Manager", Ct);

            rm.Verify(x => x.CreateAsync(It.Is<ApplicationRole>(r => r.Name == "Manager")), Times.Once);

            // Failure path
            rm.Reset();
            rm.Setup(x => x.RoleExistsAsync("Operator")).ReturnsAsync(false);
            rm.Setup(x => x.CreateAsync(It.IsAny<ApplicationRole>()))
              .ReturnsAsync(IdentityResult.Failed(new IdentityError { Code = "Err", Description = "fail" }));

            var repo2 = new UserRepository(db, um.Object, rm.Object);
            var act = async () => await repo2.EnsureRoleExistsAsync("Operator", Ct);
            await act.Should().ThrowAsync<InvalidOperationException>()
               .WithMessage("*Err:fail*");
        }

        [Fact]
        public async Task AddToRole_ShouldAdd_WhenUserExists_AndRoleExists_ElseCreateRole_AndThrowOnFailure()
        {
            var db = CreateInMemoryDbContext();
            var um = CreateUserManagerMock();
            var rm = CreateRoleManagerMock();

            var user = new ApplicationUser { Id = Guid.NewGuid(), Email = "user@test.local", UserName = "user@test.local", NomeCompleto = "User" };

            um.Setup(x => x.FindByIdAsync(user.Id.ToString())).ReturnsAsync(user);
            rm.Setup(x => x.RoleExistsAsync("User")).ReturnsAsync(true);
            um.Setup(x => x.AddToRoleAsync(user, "User")).ReturnsAsync(IdentityResult.Success);

            var repo = new UserRepository(db, um.Object, rm.Object);
            await repo.AddToRoleAsync(user.Id, "User", Ct);

            um.Verify(x => x.AddToRoleAsync(user, "User"), Times.Once);

            // When user not found
            um.Reset();
            rm.Reset();
            um.Setup(x => x.FindByIdAsync(user.Id.ToString())).ReturnsAsync((ApplicationUser?)null);

            var repo2 = new UserRepository(db, um.Object, rm.Object);
            var actNotFound = async () => await repo2.AddToRoleAsync(user.Id, "User", Ct);
            await actNotFound.Should().ThrowAsync<InvalidOperationException>()
               .WithMessage("*Usuário não encontrado*");

            // When role missing and created then add
            um.Reset();
            rm.Reset();
            um.Setup(x => x.FindByIdAsync(user.Id.ToString())).ReturnsAsync(user);
            rm.Setup(x => x.RoleExistsAsync("Admin")).ReturnsAsync(false);
            rm.Setup(x => x.CreateAsync(It.IsAny<ApplicationRole>())).ReturnsAsync(IdentityResult.Success);
            um.Setup(x => x.AddToRoleAsync(user, "Admin")).ReturnsAsync(IdentityResult.Success);

            var repo3 = new UserRepository(db, um.Object, rm.Object);
            await repo3.AddToRoleAsync(user.Id, "Admin", Ct);

            // When add fails
            um.Reset();
            rm.Reset();
            um.Setup(x => x.FindByIdAsync(user.Id.ToString())).ReturnsAsync(user);
            rm.Setup(x => x.RoleExistsAsync("Editor")).ReturnsAsync(true);
            um.Setup(x => x.AddToRoleAsync(user, "Editor"))
              .ReturnsAsync(IdentityResult.Failed(new IdentityError { Code = "E", Description = "cannot add" }));

            var repo4 = new UserRepository(db, um.Object, rm.Object);
            var actFail = async () => await repo4.AddToRoleAsync(user.Id, "Editor", Ct);
            await actFail.Should().ThrowAsync<InvalidOperationException>()
               .WithMessage("*E:cannot add*");
        }

        [Fact]
        public async Task IsEmailConfirmed_GenerateAndConfirmEmail_Tokens()
        {
            var db = CreateInMemoryDbContext();
            var um = CreateUserManagerMock();
            var rm = CreateRoleManagerMock();
            var user = new ApplicationUser { Id = Guid.NewGuid(), Email = "x@test.local", UserName = "x@test.local", NomeCompleto = "User" };

            um.Setup(x => x.FindByIdAsync(user.Id.ToString())).ReturnsAsync(user);
            um.Setup(x => x.IsEmailConfirmedAsync(user)).ReturnsAsync(true);
            um.Setup(x => x.GenerateEmailConfirmationTokenAsync(user)).ReturnsAsync("TOKEN");
            um.Setup(x => x.ConfirmEmailAsync(user, "TOKEN")).ReturnsAsync(IdentityResult.Success);

            var repo = new UserRepository(db, um.Object, rm.Object);

            (await repo.IsEmailConfirmedAsync(user.Id, Ct)).Should().BeTrue();
            (await repo.GenerateEmailConfirmationTokenAsync(user.Id, Ct)).Should().Be("TOKEN");
            await repo.ConfirmEmailAsync(user.Id, "TOKEN", Ct);

            // Not found path
            um.Reset();
            um.Setup(x => x.FindByIdAsync(user.Id.ToString())).ReturnsAsync((ApplicationUser?)null);
            var repo2 = new UserRepository(db, um.Object, rm.Object);

            var act1 = async () => await repo2.GenerateEmailConfirmationTokenAsync(user.Id, Ct);
            await act1.Should().ThrowAsync<InvalidOperationException>()
                .WithMessage("*Usuário não encontrado*");

            var act2 = async () => await repo2.ConfirmEmailAsync(user.Id, "X", Ct);
            await act2.Should().ThrowAsync<InvalidOperationException>()
                .WithMessage("*Usuário não encontrado*");

            // Failed confirm
            um.Reset();
            um.Setup(x => x.FindByIdAsync(user.Id.ToString())).ReturnsAsync(user);
            um.Setup(x => x.ConfirmEmailAsync(user, "BAD"))
              .ReturnsAsync(IdentityResult.Failed(new IdentityError { Code = "Bad", Description = "invalid token" }));

            var repo3 = new UserRepository(db, um.Object, rm.Object);
            var act3 = async () => await repo3.ConfirmEmailAsync(user.Id, "BAD", Ct);
            await act3.Should().ThrowAsync<InvalidOperationException>()
               .WithMessage("*Bad:invalid token*");
        }

        [Fact]
        public async Task GenerateAndResetPassword_ShouldThrowWhenInvalid()
        {
            var db = CreateInMemoryDbContext();
            var um = CreateUserManagerMock();
            var rm = CreateRoleManagerMock();
            var user = new ApplicationUser { Id = Guid.NewGuid(), Email = "reset@test.local", UserName = "reset@test.local", NomeCompleto = "User" };

            um.Setup(x => x.FindByIdAsync(user.Id.ToString())).ReturnsAsync(user);
            um.Setup(x => x.GeneratePasswordResetTokenAsync(user)).ReturnsAsync("RST");
            um.Setup(x => x.ResetPasswordAsync(user, "RST", "NewP@ss!")).ReturnsAsync(IdentityResult.Success);

            var repo = new UserRepository(db, um.Object, rm.Object);

            (await repo.GeneratePasswordResetTokenAsync(user.Id, Ct)).Should().Be("RST");
            await repo.ResetPasswordAsync(user.Id, "RST", "NewP@ss!", Ct);

            // Invalid token
            um.Reset();
            um.Setup(x => x.FindByIdAsync(user.Id.ToString())).ReturnsAsync(user);
            um.Setup(x => x.ResetPasswordAsync(user, "BAD", "x"))
              .ReturnsAsync(IdentityResult.Failed(new IdentityError { Code = "Bad", Description = "invalid" }));

            var repo2 = new UserRepository(db, um.Object, rm.Object);
            var act = async () => await repo2.ResetPasswordAsync(user.Id, "BAD", "x", Ct);
            await act.Should().ThrowAsync<InvalidOperationException>()
               .WithMessage("*Bad:invalid*");
        }

        [Fact]
        public async Task CheckPassword_And_GetRoles_ShouldBehave_WhenUserMissingOrPresent()
        {
            var db = CreateInMemoryDbContext();
            var um = CreateUserManagerMock();
            var rm = CreateRoleManagerMock();

            var user = new ApplicationUser { Id = Guid.NewGuid(), Email = "user@test.local", UserName = "user@test.local", NomeCompleto = "User" };

            // Missing user
            um.Setup(x => x.FindByIdAsync(user.Id.ToString())).ReturnsAsync((ApplicationUser?)null);
            var repo = new UserRepository(db, um.Object, rm.Object);

            (await repo.CheckPasswordAsync(user.Id, "x", Ct)).Should().BeFalse();
            (await repo.GetRolesAsync(user.Id, Ct)).Should().BeEmpty();

            // Present user
            um.Reset();
            um.Setup(x => x.FindByIdAsync(user.Id.ToString())).ReturnsAsync(user);
            um.Setup(x => x.CheckPasswordAsync(user, "good")).ReturnsAsync(true);
            um.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(new List<string> { "User", "Admin" });

            var repo2 = new UserRepository(db, um.Object, rm.Object);
            (await repo2.CheckPasswordAsync(user.Id, "good", Ct)).Should().BeTrue();
            (await repo2.GetRolesAsync(user.Id, Ct)).Should().BeEquivalentTo(new[] { "User", "Admin" });
        }

        [Fact]
        public async Task RefreshToken_CRUD_And_MostRecentActive()
        {
            var db = CreateInMemoryDbContext();
            var um = CreateUserManagerMock();
            var rm = CreateRoleManagerMock();
            var repo = new UserRepository(db, um.Object, rm.Object);

            var uid = Guid.NewGuid();

            var t1 = NewToken(uid, minutesAhead: 120);
            var t2 = NewToken(uid, minutesAhead: 10);
            var t3 = NewToken(uid, minutesAhead: 240);

            await repo.AddRefreshTokenAsync(t1, Ct);
            await repo.AddRefreshTokenAsync(t2, Ct);
            await repo.AddRefreshTokenAsync(t3, Ct);

            // Update token (revoke one)
            t2.Revoke("manual", "127.0.0.1");
            await repo.UpdateRefreshTokenAsync(t2, Ct);

            var fetched = await repo.GetRefreshTokenAsync(t1.Id, Ct);
            fetched.Should().NotBeNull();
            fetched!.Id.Should().Be(t1.Id);

            var mostRecentActive = await repo.GetMostRecentActiveTokenAsync(uid, Ct);
            mostRecentActive.Should().NotBeNull();
            mostRecentActive!.Id.Should().Be(t3.Id);
        }

        [Fact]
        public async Task RevokeTokenCascade_ShouldRevokeWholeChain_MultipleNodes()
        {
            var db = CreateInMemoryDbContext();
            var um = CreateUserManagerMock();
            var rm = CreateRoleManagerMock();
            var repo = new UserRepository(db, um.Object, rm.Object);

            var uid = Guid.NewGuid();
            var a = NewToken(uid, 300);
            var b = NewToken(uid, 300);
            var c = NewToken(uid, 300);

            // Forge chain: a -> b -> c (not revoked yet)
            SetPrivate(a, nameof(RefreshToken.ReplacedByTokenId), b.Id);
            SetPrivate(b, nameof(RefreshToken.ReplacedByTokenId), c.Id);

            await repo.AddRefreshTokenAsync(a, Ct);
            await repo.AddRefreshTokenAsync(b, Ct);
            await repo.AddRefreshTokenAsync(c, Ct);

            await repo.RevokeTokenCascadeAsync(a, reason: null, revokedByIp: "127.0.0.1", Ct);

            var A = await repo.GetRefreshTokenAsync(a.Id, Ct);
            var B = await repo.GetRefreshTokenAsync(b.Id, Ct);
            var C = await repo.GetRefreshTokenAsync(c.Id, Ct);

            A!.RevokedAt.Should().NotBeNull();
            B!.RevokedAt.Should().NotBeNull();
            C!.RevokedAt.Should().NotBeNull();

            // Default reason when null
            A.ReasonRevoked.Should().Be("Revogado em cascata");
            B.ReasonRevoked.Should().Be("Revogado em cascata");
            C.ReasonRevoked.Should().Be("Revogado em cascata");
        }

        [Fact]
        public async Task UpsertAndGetProfile_ShouldInsertAndUpdate()
        {
            var db = CreateInMemoryDbContext();
            var um = CreateUserManagerMock();
            var rm = CreateRoleManagerMock();
            var repo = new UserRepository(db, um.Object, rm.Object);

            var uid = Guid.NewGuid();
            var profile = new UserProfile(uid, "User Name", DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-30)));

            await repo.UpsertProfileAsync(profile, Ct);

            var loaded = await repo.GetProfileAsync(uid, Ct);
            loaded.Should().NotBeNull();
            loaded!.NomeCompleto.Should().Be("User Name");

            profile.SetNomeCompleto("User Name 2");
            await repo.UpsertProfileAsync(profile, Ct);

            var loaded2 = await repo.GetProfileAsync(uid, Ct);
            loaded2!.NomeCompleto.Should().Be("User Name 2");
        }
    }
}