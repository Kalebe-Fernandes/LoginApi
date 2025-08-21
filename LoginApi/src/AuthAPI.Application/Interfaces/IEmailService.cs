namespace AuthAPI.Application.Interfaces
{
    // Serviço de Email
    public interface IEmailService
    {
        Task SendEmailConfirmationAsync(string toEmail, string confirmationLink, string? toName, CancellationToken ct);
        Task SendPasswordResetAsync(string toEmail, string resetLink, string? toName, CancellationToken ct);
    }
}