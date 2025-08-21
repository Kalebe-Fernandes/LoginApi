using AuthAPI.Application.DTOs;
using AuthAPI.Application.Interfaces;

namespace AuthAPI.Application.Handlers
{
    // Commands/Queries
    public sealed record RegisterUserCommand(string Email, string Password, string NomeCompleto, DateOnly DataDeNascimento);
    public sealed record RegisterUserResult(Guid UserId, string EmailConfirmationToken);

    public sealed record LoginQuery(string Email, string Password, string? IpAddress);
    public sealed record LoginResult(AuthResponse Response);

    // Handlers
    public sealed class RegisterUserCommandHandler(IUserRepository users, IUnitOfWork uow)
    {
        private readonly IUserRepository _users = users;
        private readonly IUnitOfWork _uow = uow;

        public async Task<RegisterUserResult> Handle(RegisterUserCommand cmd, CancellationToken ct)
        {
            await _uow.BeginAsync(ct);

            try
            {
                if (await _users.EmailExistsAsync(cmd.Email, ct))
                    throw new InvalidOperationException("Email já cadastrado.");

                var userId = await _users.CreateUserAsync(cmd.Email, cmd.Password, cmd.NomeCompleto, cmd.DataDeNascimento, ct);

                // Garantir role "User" e atribuição
                await _users.EnsureRoleExistsAsync("User", ct);
                await _users.AddToRoleAsync(userId, "User", ct);

                // Token de confirmação de email
                var confirmToken = await _users.GenerateEmailConfirmationTokenAsync(userId, ct);

                await _uow.CommitAsync(ct);
                return new RegisterUserResult(userId, confirmToken);
            }
            catch
            {
                await _uow.RollbackAsync(ct);
                throw;
            }
        }
    }

    public sealed class LoginQueryHandler(IUserRepository users, ITokenService tokens)
    {
        private readonly IUserRepository _users = users;
        private readonly ITokenService _tokens = tokens;

        public async Task<LoginResult> Handle(LoginQuery query, CancellationToken ct)
        {
            var userId = await _users.GetUserIdByEmailAsync(query.Email, ct)
                        ?? throw new InvalidOperationException("Credenciais inválidas.");

            if (!await _users.CheckPasswordAsync(userId, query.Password, ct))
                throw new InvalidOperationException("Credenciais inválidas.");

            if (!await _users.IsEmailConfirmedAsync(userId, ct))
                throw new InvalidOperationException("Email não confirmado.");

            var roles = await _users.GetRolesAsync(userId, ct);
            var access = _tokens.GenerateAccessToken(userId, query.Email, roles);
            var refresh = _tokens.CreateRefreshToken(userId, query.IpAddress, lifetime: null);

            // Persistir refresh token
            await _users.AddRefreshTokenAsync(refresh.Entity, ct);

            var resp = new AuthResponse(
                access.Token,
                access.ExpiresAt,
                refresh.PlainText,
                refresh.ExpiresAt
            );

            return new LoginResult(resp);
        }
    }
}