namespace AuthAPI.Infrastructure.Configurations
{
    public sealed class SmtpOptions
    {
        public const string SectionName = "Smtp";

        public string Host { get; set; } = default!;
        public int Port { get; set; } = 587;
        public bool UseSsl { get; set; } = false;       // SMTPS 465
        public bool UseStartTls { get; set; } = true;   // STARTTLS 587

        public string FromName { get; set; } = "AuthAPI";
        public string FromEmail { get; set; } = default!;

        public string Username { get; set; } = default!;
        public string Password { get; set; } = default!;
    }
}