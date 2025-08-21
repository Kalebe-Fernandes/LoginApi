using AutoFixture;
using AuthAPI.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AuthAPI.Tests.Tests.Shared
{
    /// <summary>
    /// Classe base para testes unitários. Fornece acesso ao TestFixture, helpers
    /// para criação de DbContext em memória e um ILogger<T> nulo.
    /// </summary>
    public abstract class TestBase(TestFixture fixture)
    {

        /// <summary>
        /// Fixture compartilhada (AutoFixture, CancellationToken, etc.).
        /// </summary>
        protected TestFixture Fixture { get; } = fixture ?? throw new ArgumentNullException(nameof(fixture));

        /// <summary>
        /// Atalho para o AutoFixture.
        /// </summary>
        protected IFixture Auto => Fixture.Fixture;

        /// <summary>
        /// Token de cancelamento padrão para operações assíncronas de teste.
        /// </summary>
        protected CancellationToken Ct => Fixture.Ct;

        /// <summary>
        /// Retorna um logger nulo (descarta logs).
        /// </summary>
        protected ILogger<T> GetNullLogger<T>() => NullLogger<T>.Instance;

        /// <summary>
        /// Cria um AuthDbContext usando o provedor InMemory (isolado por nome).
        /// </summary>
        protected AuthDbContext CreateInMemoryDbContext(string? dbName = null)
        {
            var options = new DbContextOptionsBuilder<AuthDbContext>()
                .UseInMemoryDatabase(dbName ?? $"AuthApi_Unit_{Guid.NewGuid():N}")
                .Options;

            return new AuthDbContext(options);
        }
    }
}