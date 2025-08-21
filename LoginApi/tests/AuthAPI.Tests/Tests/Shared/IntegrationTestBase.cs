using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthAPI.Tests.Tests.Shared
{
    /// <summary>
    /// Classe base para testes de integração.
    /// Fornece HttpClient e acesso aos serviços do host de teste.
    /// </summary>
    public abstract class IntegrationTestBase : IDisposable
    {
        protected IntegrationTestBase()
        {
            Factory = new WebAppFactory();
            Client = Factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false
            });
        }

        protected WebAppFactory Factory { get; }
        protected HttpClient Client { get; }

        /// <summary>
        /// Resolve um serviço registrado no host de teste.
        /// </summary>
        protected T GetService<T>() where T : notnull
            => Factory.Services.GetRequiredService<T>();

        public void Dispose()
        {
            Client.Dispose();
            Factory.Dispose();
        }
    }
}