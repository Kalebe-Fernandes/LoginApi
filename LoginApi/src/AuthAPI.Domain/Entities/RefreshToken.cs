namespace AuthAPI.Domain.Entities
{
    public class RefreshToken
    {
        public Guid Id { get; private set; } = Guid.NewGuid();

        // Association
        public Guid UserId { get; private set; }

        // Security - store only hash + salt
        public string TokenHash { get; private set; } = default!;
        public string TokenSalt { get; private set; } = default!;

        // Metadata
        public DateTimeOffset ExpiresAt { get; private set; }
        public DateTimeOffset CreatedAt { get; private set; } = DateTimeOffset.UtcNow;
        public string? CreatedByIp { get; private set; }

        // Revocation
        public DateTimeOffset? RevokedAt { get; private set; }
        public string? RevokedByIp { get; private set; }
        public string? ReasonRevoked { get; private set; }

        // Rotation (link to new token)
        public Guid? ReplacedByTokenId { get; private set; }

        public bool IsExpired => DateTimeOffset.UtcNow >= ExpiresAt;
        public bool IsRevoked => RevokedAt.HasValue;
        public bool IsActive => !IsRevoked && !IsExpired;

        private RefreshToken() { }

        public RefreshToken(Guid userId, string tokenHash, string tokenSalt, DateTimeOffset expiresAt, string? createdByIp)
        {
            if (userId == Guid.Empty) throw new ArgumentException("UserId inválido.", nameof(userId));
            if (string.IsNullOrWhiteSpace(tokenHash)) throw new ArgumentException("TokenHash é obrigatório.", nameof(tokenHash));
            if (string.IsNullOrWhiteSpace(tokenSalt)) throw new ArgumentException("TokenSalt é obrigatório.", nameof(tokenSalt));
            if (expiresAt <= DateTimeOffset.UtcNow) throw new ArgumentException("A expiração deve ser futura.", nameof(expiresAt));

            UserId = userId;
            TokenHash = tokenHash;
            TokenSalt = tokenSalt;
            ExpiresAt = expiresAt;
            CreatedByIp = createdByIp;
        }

        public void Revoke(string? reason, string? revokedByIp)
        {
            if (IsRevoked) return;
            RevokedAt = DateTimeOffset.UtcNow;
            RevokedByIp = revokedByIp;
            ReasonRevoked = string.IsNullOrWhiteSpace(reason) ? "Revogado" : reason;
        }

        public void ReplaceBy(Guid newTokenId, string? reason = "Rotated")
        {
            if (newTokenId == Guid.Empty) throw new ArgumentException("Novo token inválido.", nameof(newTokenId));
            ReplacedByTokenId = newTokenId;
            Revoke(reason, revokedByIp: null);
        }

        public void SetCrypto(string tokenHash, string tokenSalt)
        {
            if (string.IsNullOrWhiteSpace(tokenHash)) throw new ArgumentException("TokenHash é obrigatório.", nameof(tokenHash));
            if (string.IsNullOrWhiteSpace(tokenSalt)) throw new ArgumentException("TokenSalt é obrigatório.", nameof(tokenSalt));
            TokenHash = tokenHash;
            TokenSalt = tokenSalt;
        }
    }
}