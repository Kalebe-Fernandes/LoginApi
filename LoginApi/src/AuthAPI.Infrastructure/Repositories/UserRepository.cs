using AuthAPI.Application.Interfaces;
using AuthAPI.Domain.Entities;
using AuthAPI.Infrastructure.Data;
using AuthAPI.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AuthAPI.Infrastructure.Repositories
{
    public sealed class UserRepository(AuthDbContext db, UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager) : IUserRepository
    {
        private readonly AuthDbContext _db = db;
        private readonly UserManager<ApplicationUser> _userManager = userManager;
        private readonly RoleManager<ApplicationRole> _roleManager = roleManager;

        public async Task<bool> EmailExistsAsync(string email, CancellationToken ct)
        {
            var user = await _userManager.FindByEmailAsync(email);
            return user is not null;
        }

        public async Task<Guid?> GetUserIdByEmailAsync(string email, CancellationToken ct)
        {
            var user = await _userManager.FindByEmailAsync(email);
            return user?.Id;
        }

        public async Task<string?> GetEmailByUserIdAsync(Guid userId, CancellationToken ct)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            return user?.Email;
        }

        public async Task<Guid> CreateUserAsync(string email, string password, string nomeCompleto, DateOnly? dataDeNascimento, CancellationToken ct)
        {
            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = email,
                Email = email,
                NomeCompleto = nomeCompleto,
                DataDeNascimento = dataDeNascimento
            };

            var result = await _userManager.CreateAsync(user, password);
            if (!result.Succeeded)
            {
                var errors = string.Join("; ", result.Errors.Select(e => $"{e.Code}:{e.Description}"));
                throw new InvalidOperationException($"Falha ao criar usuário: {errors}");
            }

            // Cria perfil de domínio sincronizado
            var profile = new UserProfile(user.Id, nomeCompleto, dataDeNascimento);
            _db.UserProfiles.Add(profile);

            await _db.SaveChangesAsync(ct);
            return user.Id;
        }

        public async Task UpsertProfileAsync(UserProfile profile, CancellationToken ct)
        {
            var exists = await _db.UserProfiles.AsNoTracking().AnyAsync(p => p.Id == profile.Id, ct);
            if (exists)
            {
                _db.UserProfiles.Update(profile);
            }
            else
            {
                _db.UserProfiles.Add(profile);
            }
            await _db.SaveChangesAsync(ct);
        }

        public Task<UserProfile?> GetProfileAsync(Guid userId, CancellationToken ct)
        {
            return _db.UserProfiles.AsNoTracking().FirstOrDefaultAsync(p => p.Id == userId, ct);
        }

        public async Task<bool> CheckPasswordAsync(Guid userId, string password, CancellationToken ct)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user is null) return false;
            return await _userManager.CheckPasswordAsync(user, password);
        }

        public async Task<IReadOnlyList<string>> GetRolesAsync(Guid userId, CancellationToken ct)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user is null) return Array.Empty<string>();
            var roles = await _userManager.GetRolesAsync(user);
            return [.. roles];
        }

        public async Task EnsureRoleExistsAsync(string roleName, CancellationToken ct)
        {
            if (!await _roleManager.RoleExistsAsync(roleName))
            {
                var created = await _roleManager.CreateAsync(new ApplicationRole(roleName));
                if (!created.Succeeded)
                {
                    var errors = string.Join("; ", created.Errors.Select(e => $"{e.Code}:{e.Description}"));
                    throw new InvalidOperationException($"Falha ao criar role '{roleName}': {errors}");
                }
            }
        }

        public async Task AddToRoleAsync(Guid userId, string roleName, CancellationToken ct)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user is null) throw new InvalidOperationException("Usuário não encontrado.");
            if (!await _roleManager.RoleExistsAsync(roleName))
            {
                await EnsureRoleExistsAsync(roleName, ct);
            }
            var res = await _userManager.AddToRoleAsync(user, roleName);
            if (!res.Succeeded)
            {
                var errors = string.Join("; ", res.Errors.Select(e => $"{e.Code}:{e.Description}"));
                throw new InvalidOperationException($"Falha ao adicionar role '{roleName}': {errors}");
            }
        }

        public async Task<bool> IsEmailConfirmedAsync(Guid userId, CancellationToken ct)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user is null) return false;
            return await _userManager.IsEmailConfirmedAsync(user);
        }

        public async Task<string> GenerateEmailConfirmationTokenAsync(Guid userId, CancellationToken ct)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString())
                       ?? throw new InvalidOperationException("Usuário não encontrado.");
            return await _userManager.GenerateEmailConfirmationTokenAsync(user);
        }

        public async Task ConfirmEmailAsync(Guid userId, string token, CancellationToken ct)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString())
                       ?? throw new InvalidOperationException("Usuário não encontrado.");
            var res = await _userManager.ConfirmEmailAsync(user, token);
            if (!res.Succeeded)
            {
                var errors = string.Join("; ", res.Errors.Select(e => $"{e.Code}:{e.Description}"));
                throw new InvalidOperationException($"Falha ao confirmar email: {errors}");
            }
        }

        public async Task<string> GeneratePasswordResetTokenAsync(Guid userId, CancellationToken ct)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString())
                       ?? throw new InvalidOperationException("Usuário não encontrado.");
            return await _userManager.GeneratePasswordResetTokenAsync(user);
        }

        public async Task ResetPasswordAsync(Guid userId, string token, string newPassword, CancellationToken ct)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString())
                       ?? throw new InvalidOperationException("Usuário não encontrado.");
            var res = await _userManager.ResetPasswordAsync(user, token, newPassword);
            if (!res.Succeeded)
            {
                var errors = string.Join("; ", res.Errors.Select(e => $"{e.Code}:{e.Description}"));
                throw new InvalidOperationException($"Falha ao redefinir senha: {errors}");
            }
        }

        // Refresh Tokens

        public async Task AddRefreshTokenAsync(RefreshToken entity, CancellationToken ct)
        {
            await _db.RefreshTokens.AddAsync(entity, ct);
            await _db.SaveChangesAsync(ct);
        }

        public async Task UpdateRefreshTokenAsync(RefreshToken entity, CancellationToken ct)
        {
            _db.RefreshTokens.Update(entity);
            await _db.SaveChangesAsync(ct);
        }
        public Task<RefreshToken?> GetRefreshTokenAsync(Guid tokenId, CancellationToken ct)
        {
            return _db.RefreshTokens.AsNoTracking().FirstOrDefaultAsync(t => t.Id == tokenId, ct);
        }

        public async Task<RefreshToken?> GetMostRecentActiveTokenAsync(Guid userId, CancellationToken ct)
        {
            return await _db.RefreshTokens
                .Where(t => t.UserId == userId && t.RevokedAt == null && t.ExpiresAt > DateTimeOffset.UtcNow)
                .OrderByDescending(t => t.CreatedAt)
                .FirstOrDefaultAsync(ct);
        }

        public async Task RevokeTokenCascadeAsync(RefreshToken entity, string? reason, string? revokedByIp, CancellationToken ct)
        {
            // Carrega a cadeia de substituições e revoga tudo
            var toProcess = new List<RefreshToken> { entity };
            var current = entity;

            while (current.ReplacedByTokenId.HasValue)
            {
                var next = await _db.RefreshTokens.FirstOrDefaultAsync(t => t.Id == current.ReplacedByTokenId.Value, ct);
                if (next is null) break;
                toProcess.Add(next);
                current = next;
            }

            var now = DateTimeOffset.UtcNow;
            foreach (var token in toProcess)
            {
                if (token.RevokedAt is null)
                {
                    token.Revoke(reason ?? "Revogado em cascata", revokedByIp);
                    _db.RefreshTokens.Update(token);
                }
            }

            await _db.SaveChangesAsync(ct);
        }
    }
}