using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using AuthAPI.Infrastructure.Data;
using AuthAPI.Application.Interfaces;
using AuthAPI.Tests.Tests.TestControllers;

namespace AuthAPI.Tests.Tests.Shared
{
    /// <summary>
    /// WebApplicationFactory customizada para testes de integração.
    /// - Define ambiente "Test"
    /// - Carrega appsettings.Test.json (quando existir)
    /// - Substitui o AuthDbContext pelo provedor InMemory
    /// - Substitui IEmailService por TestEmailService (mock SMTP)
    /// - Adiciona endpoints de teste para validar o middleware global e pipeline JWT
    /// - Garante criação do banco em memória
    /// </summary>
    public class WebAppFactory : WebApplicationFactory<Program>
    {
        private readonly string _dbName = $"AuthApi_Int_{Guid.NewGuid():N}";

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Test");

            builder.ConfigureAppConfiguration((context, config) =>
            {
                config.AddJsonFile("appsettings.Test.json", optional: true, reloadOnChange: false);
            });

            builder.ConfigureServices(services =>
            {
                // Remove registros existentes de DbContext (SQL Server)
                var dbContextOptionsDescriptor = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<AuthDbContext>));
                if (dbContextOptionsDescriptor is not null)
                {
                    services.Remove(dbContextOptionsDescriptor);
                }

                var dbContextDescriptor = services.Where(d => d.ServiceType == typeof(AuthDbContext)).ToList();
                foreach (var d in dbContextDescriptor)
                {
                    services.Remove(d);
                }

                // Remove serviços do provedor SQL Server previamente registrados para evitar conflito com InMemory
                var providerDescriptors = services
                    .Where(d =>
                        (d.ImplementationType?.Assembly?.GetName().Name?.Contains("Microsoft.EntityFrameworkCore.SqlServer") ?? false) ||
                        (d.ServiceType.Assembly?.GetName().Name?.Contains("Microsoft.EntityFrameworkCore.SqlServer") ?? false))
                    .ToList();
                foreach (var desc in providerDescriptors)
                {
                    services.Remove(desc);
                }

                // Adiciona DbContext em memória (isolando o provedor EF para evitar conflito com SqlServer)
                services.AddDbContext<AuthDbContext>(options =>
                {
                    options.UseInMemoryDatabase(_dbName);
                    var efSp = new ServiceCollection()
                        .AddEntityFrameworkInMemoryDatabase()
                        .BuildServiceProvider();
                    options.UseInternalServiceProvider(efSp);
                });

                // Substitui o serviço de email real por um fake para asserções
                var emailDescriptor = services.SingleOrDefault(d => d.ServiceType == typeof(IEmailService));
                if (emailDescriptor is not null)
                {
                    services.Remove(emailDescriptor);
                }
                services.AddSingleton<IEmailService, TestEmailService>();

                // Registrar controllers de teste deste assembly (ApplicationParts)
                services.AddControllers().AddApplicationPart(typeof(TestExceptionController).Assembly);

                // Constrói provedor para garantir criação do banco
                var sp = services.BuildServiceProvider();
                using var scope = sp.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
                db.Database.EnsureDeleted();
                db.Database.EnsureCreated();
            });

            // Não adicionamos middlewares customizados aqui; os testes usam controllers de teste via ApplicationParts.
            builder.Configure(app => { });
        }
    }
}