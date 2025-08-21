using SmtpServer;
using SmtpServer.Authentication;

namespace AuthAPI.Tests.Tests.Unit.Infrastructure
{
    public partial class SmtpEmailServiceTests
    {
        private sealed class CapturingUserAuthenticator : IUserAuthenticator
        {
            private readonly string? _expectedUser;
            private readonly string? _expectedPass;

            public string? LastUser { get; private set; }
            public string? LastPass { get; private set; }

            public CapturingUserAuthenticator(string? expectedUser = null, string? expectedPass = null)
            {
                _expectedUser = expectedUser;
                _expectedPass = expectedPass;
            }

            public Task<bool> AuthenticateAsync(ISessionContext context, string user, string password, CancellationToken cancellationToken)
            {
                LastUser = user;
                LastPass = password;
                if (_expectedUser is null) return Task.FromResult(true);
                return Task.FromResult(string.Equals(user, _expectedUser) && string.Equals(password, _expectedPass));
            }
        }
    }
}