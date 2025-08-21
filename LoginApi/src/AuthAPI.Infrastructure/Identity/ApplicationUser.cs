using Microsoft.AspNetCore.Identity;
using AuthAPI.Domain.Entities;

namespace AuthAPI.Infrastructure.Identity
{
    // Entidade Identity personalizada com campos adicionais solicitados
    public class ApplicationUser : IdentityUser<Guid>
    {
        public string NomeCompleto { get; set; } = default!;
        public DateOnly? DataDeNascimento { get; set; }

        // Navegações úteis para Infra (Domain permanece puro e independente)
        public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = new HashSet<RefreshToken>();
        public virtual UserProfile? Profile { get; set; }
    }
}