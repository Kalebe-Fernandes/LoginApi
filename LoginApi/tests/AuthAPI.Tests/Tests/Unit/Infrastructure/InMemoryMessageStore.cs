using System.Buffers;
using MimeKit;
using SmtpServer;
using SmtpServer.Protocol;
using SmtpServer.Storage;

namespace AuthAPI.Tests.Tests.Unit.Infrastructure
{
    public partial class SmtpEmailServiceTests
    {
        // Helpers for in-proc SMTP server (SmtpServer package)
        private sealed class InMemoryMessageStore(List<MimeMessage> messages) : IMessageStore
        {
            private readonly List<MimeMessage> _messages = messages;

            public Task<SmtpResponse> SaveAsync(ISessionContext context, IMessageTransaction transaction, ReadOnlySequence<byte> buffer, CancellationToken cancellationToken)
            {
                using var ms = new MemoryStream();
                foreach (var segment in buffer)
                {
                    var span = segment.Span;
                    ms.Write(span);
                }
                ms.Position = 0;
                var message = MimeMessage.Load(ms);
                _messages.Add(message);
                return Task.FromResult(SmtpResponse.Ok);
            }
        }
    }
}