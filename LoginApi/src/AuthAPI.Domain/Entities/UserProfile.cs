using AuthAPI.Domain.Enums;

namespace AuthAPI.Domain.Entities
{
    // Entidade de domínio pura que guarda dados de perfil do usuário,
    // mantendo a camada Domain independente do ASP.NET Identity.
    public class UserProfile
    {
        public Guid Id { get; private set; } // Deve coincidir com o Id do IdentityUser<Guid> na Infra
        public string NomeCompleto { get; private set; } = default!;
        public DateOnly? DataDeNascimento { get; private set; }
        public UserStatus Status { get; private set; } = UserStatus.PendingEmailConfirmation;

        public DateTimeOffset CreatedAt { get; private set; } = DateTimeOffset.UtcNow;
        public DateTimeOffset? UpdatedAt { get; private set; }

        private UserProfile() { }

        public UserProfile(Guid id, string nomeCompleto, DateOnly? dataDeNascimento)
        {
            if (id == Guid.Empty) throw new ArgumentException("Id inválido.", nameof(id));
            SetNomeCompleto(nomeCompleto);
            Id = id;
            DataDeNascimento = dataDeNascimento;
        }

        public void Ativar()
        {
            Status = UserStatus.Active;
            Touch();
        }

        public void Suspender()
        {
            Status = UserStatus.Suspended;
            Touch();
        }

        public void Excluir()
        {
            Status = UserStatus.Deleted;
            Touch();
        }

        public void SetNomeCompleto(string nomeCompleto)
        {
            if (string.IsNullOrWhiteSpace(nomeCompleto))
                throw new ArgumentException("Nome completo é obrigatório.", nameof(nomeCompleto));
            NomeCompleto = nomeCompleto.Trim();
            Touch();
        }

        public void SetDataDeNascimento(DateOnly? data)
        {
            if (data.HasValue && data.Value > DateOnly.FromDateTime(DateTime.UtcNow))
                throw new ArgumentException("Data de nascimento não pode ser futura.", nameof(data));
            DataDeNascimento = data;
            Touch();
        }

        private void Touch() => UpdatedAt = DateTimeOffset.UtcNow;
    }
}