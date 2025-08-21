using AuthAPI.Application.Interfaces;
using AuthAPI.Infrastructure.Configurations;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace AuthAPI.Infrastructure.Services
{
    public sealed class SmtpEmailService : IEmailService
    {
        private readonly SmtpOptions _options;

        public SmtpEmailService(IOptions<SmtpOptions> options)
        {
            _options = options.Value;
        }

        public async Task SendEmailConfirmationAsync(string toEmail, string confirmationLink, string? toName, CancellationToken ct)
        {
            var subject = "Confirme seu email - AuthAPI";
            var html = $@"
<p>Olá{(string.IsNullOrWhiteSpace(toName) ? string.Empty : $" {toName}")},</p>
<p>Obrigado por se registrar. Para concluir o cadastro, confirme seu email clicando no link abaixo:</p>
<p><a href=""{confirmationLink}"">Confirmar email</a></p>
<p>Se você não solicitou esta ação, ignore este email.</p>
<hr/>
<p>AuthAPI</p>";

            await SendAsync(toEmail, subject, html, ct);
        }

        public async Task SendPasswordResetAsync(string toEmail, string resetLink, string? toName, CancellationToken ct)
        {
            var subject = "Redefinição de senha - AuthAPI";
            var html = $@"
<p>Olá{(string.IsNullOrWhiteSpace(toName) ? string.Empty : $" {toName}")},</p>
<p>Recebemos uma solicitação para redefinir sua senha.</p>
<p>Use o link abaixo para criar uma nova senha:</p>
<p><a href=""{resetLink}"">Redefinir senha</a></p>
<p>Se você não solicitou esta ação, ignore este email.</p>
<hr/>
<p>AuthAPI</p>";

            await SendAsync(toEmail, subject, html, ct);
        }

        private async Task SendAsync(string toEmail, string subject, string htmlBody, CancellationToken ct)
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(_options.FromName ?? "AuthAPI", _options.FromEmail));
            message.To.Add(new MailboxAddress(toEmail, toEmail));
            message.Subject = subject;

            var builder = new BodyBuilder
            {
                HtmlBody = htmlBody
            };
            message.Body = builder.ToMessageBody();

            using var smtp = new SmtpClient();
            var secure = _options.UseSsl ? SecureSocketOptions.SslOnConnect
                       : _options.UseStartTls ? SecureSocketOptions.StartTls
                       : SecureSocketOptions.Auto;

            await smtp.ConnectAsync(_options.Host, _options.Port, secure, ct);

            if (!string.IsNullOrWhiteSpace(_options.Username))
            {
                await smtp.AuthenticateAsync(_options.Username, _options.Password, ct);
            }

            await smtp.SendAsync(message, ct);
            await smtp.DisconnectAsync(true, ct);
        }
    }
}