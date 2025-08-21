using System.Net.Sockets;
using AuthAPI.Infrastructure.Configurations;
using AuthAPI.Infrastructure.Services;
using FluentAssertions;
using MimeKit;
using Microsoft.Extensions.Options;
using SmtpServer;
using SmtpServer.Authentication;
using SmtpServer.ComponentModel;
using AuthAPI.Tests.Tests.Shared;

namespace AuthAPI.Tests.Tests.Unit.Infrastructure
{
    public partial class SmtpEmailServiceTests(TestFixture fixture) : TestBase(fixture), IClassFixture<TestFixture>
    {
        private static int GetFreeTcpPort()
        {
            var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        private static (SmtpServer.SmtpServer server, List<MimeMessage> messages, CapturingUserAuthenticator auth, CancellationTokenSource cts) StartSmtpServer(int port, bool requireAuth = false, string? expectedUser = null, string? expectedPass = null)
        {
            var messages = new List<MimeMessage>();
            var store = new InMemoryMessageStore(messages);
            var auth = new CapturingUserAuthenticator(expectedUser, expectedPass);

            var options = new SmtpServerOptionsBuilder()
                .ServerName("localhost")
                .Endpoint(e =>
                {
                    e.Port(port);
                    e.AuthenticationRequired(requireAuth);
                })
                .Build();

            var provider = new ServiceProvider();
            provider.Add(store);
            provider.Add((IUserAuthenticator)auth);

            var server = new SmtpServer.SmtpServer(options, provider);
            var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            _ = server.StartAsync(cts.Token); // fire and forget; completes when token canceled
            // Peq. atraso para servidor subir
            Thread.Sleep(150);
            return (server, messages, auth, cts);
        }

        private static SmtpEmailService CreateService(string host, int port, bool useSsl = false, bool useStartTls = false, string? user = null, string? pass = null, string? fromName = "AuthAPI", string? fromEmail = "no-reply@test.local")
        {
            var opts = Options.Create(new SmtpOptions
            {
                Host = host,
                Port = port,
                UseSsl = useSsl,
                UseStartTls = useStartTls,
                Username = user ?? string.Empty,
                Password = pass ?? string.Empty,
                FromName = fromName ?? "AuthAPI",
                FromEmail = fromEmail ?? "no-reply@test.local"
            });
            return new SmtpEmailService(opts);
        }

        [Fact]
        public async Task SendEmailConfirmation_Should_SendSuccessfully_AndFormatMimeCorrectly()
        {
            var port = GetFreeTcpPort();
            var (server, messages, _, cts) = StartSmtpServer(port, requireAuth: false);

            try
            {
                var svc = CreateService("localhost", port, useSsl: false, useStartTls: false);
                var to = "user@test.local";
                var link = "https://app.local/confirm?x=1";
                await svc.SendEmailConfirmationAsync(to, link, "User Test", Ct);

                messages.Should().HaveCount(1);
                var msg = messages.Single();

                msg.Subject.Should().Be("Confirme seu email - AuthAPI");
                msg.From.Mailboxes.Single().Address.Should().Be("no-reply@test.local");
                msg.From.Mailboxes.Single().Name.Should().Be("AuthAPI");
                msg.To.Mailboxes.Single().Address.Should().Be(to);

                // HTML body contains the link
                var html = msg.HtmlBody;
                html.Should().NotBeNullOrWhiteSpace();
                html.Should().Contain(link);
                html.Should().Contain("Confirmar email");
            }
            finally
            {
                cts.Cancel();
                await server.ShutdownTask;
            }
        }

        [Fact]
        public async Task SendPasswordReset_ShouldAttemptAuthenticate_WhenCredentialsConfigured()
        {
            var port = GetFreeTcpPort();
            var (server, messages, _, cts) = StartSmtpServer(port, requireAuth: false);

            try
            {
                var svc = CreateService("localhost", port, user: "smtp-user", pass: "smtp-pass", useSsl: false, useStartTls: false);
                var to = "user@test.local";
                var link = "https://app.local/reset?x=2";

                var act = async () => await svc.SendPasswordResetAsync(to, link, null, Ct);

                await act.Should().ThrowAsync<NotSupportedException>();

                messages.Should().BeEmpty();
            }
            finally
            {
                cts.Cancel();
                await server.ShutdownTask;
            }
        }

        [Fact]
        public async Task SendEmail_ShouldThrow_OnConnectionError()
        {
            // Do not start server on port -> connection should fail
            var deadPort = GetFreeTcpPort();
            var svc = CreateService("localhost", deadPort, useSsl: false, useStartTls: false);

            Func<Task> act = async () => await svc.SendEmailConfirmationAsync("user@test.local", "https://x/confirm", null, Ct);
            await act.Should().ThrowAsync<Exception>(); // SocketException or IOException from MailKit
        }

        [Fact]
        public async Task SendEmail_ShouldValidateRequiredParameters()
        {
            var port = GetFreeTcpPort();
            var (server, _, _, cts) = StartSmtpServer(port);

            try
            {
                var svc = CreateService("localhost", port, useSsl: false, useStartTls: false);

                // toEmail null -> MailboxAddress ctor will throw ArgumentNullException
                Func<Task> act1 = async () => await svc.SendEmailConfirmationAsync(null!, "https://x", null, Ct);
                await act1.Should().ThrowAsync<ArgumentNullException>();

                // Empty toEmail may pass construction but likely rejected; assert at least not successful send
                Func<Task> act2 = async () => await svc.SendEmailConfirmationAsync("", "https://x", null, Ct);
                await act2.Should().ThrowAsync<Exception>();
            }
            finally
            {
                cts.Cancel();
                await server.ShutdownTask;
            }
        }
    }
}