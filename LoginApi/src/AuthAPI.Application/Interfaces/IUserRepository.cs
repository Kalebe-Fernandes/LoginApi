using AuthAPI.Domain.Entities;

namespace AuthAPI.Application.Interfaces
{
    // Repositório de Usuários (abstrai o Identity/EF)
    public interface IUserRepository
    {
        Task<bool> EmailExistsAsync(string email, CancellationToken ct);
        Task<Guid?> GetUserIdByEmailAsync(string email, CancellationToken ct);
        Task<string?> GetEmailByUserIdAsync(Guid userId, CancellationToken ct);

        Task<Guid> CreateUserAsync(string email, string password, string nomeCompleto, DateOnly? dataDeNascimento, CancellationToken ct);
        Task UpsertProfileAsync(UserProfile profile, CancellationToken ct);
        Task<UserProfile?> GetProfileAsync(Guid userId, CancellationToken ct);

        Task<bool> CheckPasswordAsync(Guid userId, string password, CancellationToken ct);

        Task<IReadOnlyList<string>> GetRolesAsync(Guid userId, CancellationToken ct);
        Task EnsureRoleExistsAsync(string roleName, CancellationToken ct);
        Task AddToRoleAsync(Guid userId, string roleName, CancellationToken ct);

        Task<bool> IsEmailConfirmedAsync(Guid userId, CancellationToken ct);
        Task<string> GenerateEmailConfirmationTokenAsync(Guid userId, CancellationToken ct);
        Task ConfirmEmailAsync(Guid userId, string token, CancellationToken ct);

        Task<string> GeneratePasswordResetTokenAsync(Guid userId, CancellationToken ct);
        Task ResetPasswordAsync(Guid userId, string token, string newPassword, CancellationToken ct);

        // Refresh Tokens
        Task AddRefreshTokenAsync(RefreshToken entity, CancellationToken ct);
        Task UpdateRefreshTokenAsync(RefreshToken entity, CancellationToken ct);
        Task<RefreshToken?> GetRefreshTokenAsync(Guid tokenId, CancellationToken ct);
        Task<RefreshToken?> GetMostRecentActiveTokenAsync(Guid userId, CancellationToken ct);
        Task RevokeTokenCascadeAsync(RefreshToken entity, string? reason, string? revokedByIp, CancellationToken ct);
    }
}