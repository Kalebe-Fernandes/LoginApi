using AuthAPI.Application.Interfaces;
using AuthAPI.Domain.Entities;
using AuthAPI.Infrastructure.Data;
using AuthAPI.Infrastructure.Services;
using AuthAPI.Infrastructure.Identity;
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Moq;
using AuthAPI.Tests.Tests.Shared;

namespace AuthAPI.Tests.Tests.Unit.Infrastructure
{
    public class UnitOfWorkTests(TestFixture fixture) : TestBase(fixture), IClassFixture<TestFixture>
    {
        private static (AuthDbContext db, SqliteConnection conn) CreateSqliteDb()
        {
            var conn = new SqliteConnection("DataSource=:memory:");
            conn.Open();

            var options = new DbContextOptionsBuilder<AuthDbContext>()
                .UseSqlite(conn)
                .Options;

            var db = new AuthDbContext(options);
            db.Database.EnsureCreated();
            return (db, conn);
        }

        [Fact]
        public async Task Begin_Commit_ShouldPersistChanges_AndDisposeTransaction()
        {
            var (db, conn) = CreateSqliteDb();
            await using var _ = conn;
            var repo = new Mock<IUserRepository>();
            await using var uow = new UnitOfWork(db, repo.Object);

            await uow.BeginAsync(Ct);

            var id = Guid.NewGuid();
            db.Set<ApplicationUser>().Add(new ApplicationUser
            {
                Id = id,
                Email = "user1@test.local",
                UserName = "user1@test.local",
                NomeCompleto = "User One"
            });
            db.UserProfiles.Add(new UserProfile(id, "User One", DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-20))));
            await uow.CommitAsync(Ct);

            var count = await db.UserProfiles.CountAsync(Ct);
            count.Should().Be(1);

            // Calling commit again should be a no-op and not throw
            await uow.CommitAsync(Ct);
        }

        [Fact]
        public async Task Rollback_ShouldDiscardChanges_AndResetState()
        {
            var (db, conn) = CreateSqliteDb();
            await using var _ = conn;
            var repo = new Mock<IUserRepository>();
            await using var uow = new UnitOfWork(db, repo.Object);

            await uow.BeginAsync(Ct);

            var id = Guid.NewGuid();
            db.Set<ApplicationUser>().Add(new ApplicationUser
            {
                Id = id,
                Email = "user2@test.local",
                UserName = "user2@test.local",
                NomeCompleto = "User Two"
            });
            db.UserProfiles.Add(new UserProfile(id, "User Two", DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-30))));
            await uow.RollbackAsync(Ct);

            var count = await db.UserProfiles.CountAsync(Ct);
            count.Should().Be(0);

            // Subsequent commit should not throw
            await uow.CommitAsync(Ct);
        }

        [Fact]
        public async Task Begin_Twice_ShouldNotOpenNewTransaction_UntilCommitted_ThenAllowAnotherBegin()
        {
            var (db, conn) = CreateSqliteDb();
            await using var _ = conn;
            var repo = new Mock<IUserRepository>();
            await using var uow = new UnitOfWork(db, repo.Object);

            await uow.BeginAsync(Ct);
            // Second begin should no-op
            await uow.BeginAsync(Ct);

            var id1 = Guid.NewGuid();
            db.Set<ApplicationUser>().Add(new ApplicationUser
            {
                Id = id1,
                Email = "user3@test.local",
                UserName = "user3@test.local",
                NomeCompleto = "User Three"
            });
            db.UserProfiles.Add(new UserProfile(id1, "User Three", DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-25))));
            await uow.CommitAsync(Ct);

            (await db.UserProfiles.CountAsync(Ct)).Should().Be(1);

            // Start a new transaction after commit
            await uow.BeginAsync(Ct);
            var id2 = Guid.NewGuid();
            db.Set<ApplicationUser>().Add(new ApplicationUser
            {
                Id = id2,
                Email = "user4@test.local",
                UserName = "user4@test.local",
                NomeCompleto = "User Four"
            });
            db.UserProfiles.Add(new UserProfile(id2, "User Four", DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-22))));
            await uow.CommitAsync(Ct);

            (await db.UserProfiles.CountAsync(Ct)).Should().Be(2);
        }

        [Fact]
        public async Task DisposeAsync_ShouldDisposeTransaction_Safely()
        {
            var (db, conn) = CreateSqliteDb();
            await using var _ = conn;
            var repo = new Mock<IUserRepository>();
            var uow = new UnitOfWork(db, repo.Object);

            await uow.BeginAsync(Ct);

            // Should not throw
            await uow.DisposeAsync();

            // After dispose, starting new transaction should work
            await uow.BeginAsync(Ct);
            var id = Guid.NewGuid();
            db.Set<ApplicationUser>().Add(new ApplicationUser
            {
                Id = id,
                Email = "user5@test.local",
                UserName = "user5@test.local",
                NomeCompleto = "User Five"
            });
            db.UserProfiles.Add(new UserProfile(id, "User Five", DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-19))));
            await uow.CommitAsync(Ct);
        }
    }
}