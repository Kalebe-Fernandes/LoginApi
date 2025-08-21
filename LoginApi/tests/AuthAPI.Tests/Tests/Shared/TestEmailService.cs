using System.Collections.Concurrent;
using AuthAPI.Application.Interfaces;

namespace AuthAPI.Tests.Tests.Shared
{
    public sealed class TestEmailService : IEmailService
    {
        public sealed record EmailMessage(string ToEmail, string Subject, string Body, string? ToName, string Kind, string Link);

        private readonly ConcurrentQueue<EmailMessage> _sent = new();
        public int TotalSent => _sent.Count;
        public IReadOnlyCollection<EmailMessage> Sent => _sent.ToArray();
        public EmailMessage? LastSent => _sent.LastOrDefault();
        public string? LastConfirmationLink => _sent.LastOrDefault(m => m.Kind == "confirmation")?.Link;
        public string? LastResetLink => _sent.LastOrDefault(m => m.Kind == "reset")?.Link;

        public Task SendEmailConfirmationAsync(string toEmail, string confirmationLink, string? toName, CancellationToken ct)
        {
            _sent.Enqueue(new EmailMessage(toEmail, "Confirme seu email - AuthAPI", $"CONFIRM|{confirmationLink}", toName, "confirmation", confirmationLink));
            return Task.CompletedTask;
        }

        public Task SendPasswordResetAsync(string toEmail, string resetLink, string? toName, CancellationToken ct)
        {
            _sent.Enqueue(new EmailMessage(toEmail, "Redefinição de senha - AuthAPI", $"RESET|{resetLink}", toName, "reset", resetLink));
            return Task.CompletedTask;
        }

        public void Clear() => _sent.Clear();
    }
}