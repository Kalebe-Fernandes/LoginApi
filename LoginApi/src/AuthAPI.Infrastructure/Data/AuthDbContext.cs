using AuthAPI.Domain.Entities;
using AuthAPI.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthAPI.Infrastructure.Data
{
    public class AuthDbContext(DbContextOptions<AuthDbContext> options) : IdentityDbContext<ApplicationUser, ApplicationRole, Guid>(options)
    {
        public DbSet<UserProfile> UserProfiles => Set<UserProfile>();
        public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Schema padrão para separar objetos da aplicação
            builder.HasDefaultSchema("auth");

            // Tabelas do Identity (renomeadas para manter consistência)
            builder.Entity<ApplicationUser>().ToTable("Users");
            builder.Entity<ApplicationRole>().ToTable("Roles");
            builder.Entity<IdentityUserRole<Guid>>().ToTable("UserRoles");
            builder.Entity<IdentityUserClaim<Guid>>().ToTable("UserClaims");
            builder.Entity<IdentityUserLogin<Guid>>().ToTable("UserLogins");
            builder.Entity<IdentityRoleClaim<Guid>>().ToTable("RoleClaims");
            builder.Entity<IdentityUserToken<Guid>>().ToTable("UserTokens");

            // ApplicationUser
            builder.Entity<ApplicationUser>(b =>
            {
                b.Property(u => u.NomeCompleto)
                    .HasMaxLength(200)
                    .IsRequired();

                // DateOnly - mapeia como 'date' (SQL Server)
                b.Property(u => u.DataDeNascimento)
                    .HasColumnType("date");

                // 1:N - User - RefreshTokens
                b.HasMany<RefreshToken>()
                    .WithOne()
                    .HasForeignKey(t => t.UserId)
                    .OnDelete(DeleteBehavior.Cascade);

                // 1:1 - User - UserProfile (mesmo Id)
                b.HasOne(u => u.Profile)
                    .WithOne()
                    .HasForeignKey<UserProfile>(p => p.Id)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // UserProfile
            builder.Entity<UserProfile>(b =>
            {
                b.ToTable("UserProfiles");
                b.HasKey(p => p.Id);

                b.Property(p => p.NomeCompleto)
                    .HasMaxLength(200)
                    .IsRequired();

                b.Property(p => p.DataDeNascimento)
                    .HasColumnType("date");

                b.Property(p => p.Status)
                    .HasConversion<int>();

                b.Property(p => p.CreatedAt)
                    .IsRequired();

                b.Property(p => p.UpdatedAt);
            });

            // RefreshToken
            builder.Entity<RefreshToken>(b =>
            {
                b.ToTable("RefreshTokens");
                b.HasKey(t => t.Id);

                b.Property(t => t.UserId)
                    .IsRequired();

                b.Property(t => t.TokenHash)
                    .HasMaxLength(256)
                    .IsRequired();

                b.Property(t => t.TokenSalt)
                    .HasMaxLength(128)
                    .IsRequired();

                b.Property(t => t.ExpiresAt)
                    .IsRequired();

                b.Property(t => t.CreatedAt)
                    .IsRequired();

                b.Property(t => t.CreatedByIp)
                    .HasMaxLength(64);

                b.Property(t => t.RevokedAt);
                b.Property(t => t.RevokedByIp)
                    .HasMaxLength(64);
                b.Property(t => t.ReasonRevoked)
                    .HasMaxLength(256);

                b.Property(t => t.ReplacedByTokenId);

                b.HasIndex(t => new { t.UserId, t.ExpiresAt });
                b.HasIndex(t => t.ReplacedByTokenId);
            });
        }
    }
}