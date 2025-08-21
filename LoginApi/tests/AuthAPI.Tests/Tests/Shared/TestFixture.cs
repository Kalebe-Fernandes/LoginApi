using AutoFixture;

namespace AuthAPI.Tests.Tests.Shared
{
    /// <summary>
    /// Fixture compartilhada para testes, provendo AutoFixture configurado,
    /// token de cancelamento padrão e utilitários de geração de dados.
    /// </summary>
    public class TestFixture : IDisposable
    {
        private readonly CancellationTokenSource _cts;

        public TestFixture()
        {
            _cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            Fixture = new Fixture();

            // Evita exceções de recursão em tipos que se referenciam mutuamente
            var recursiveBehaviors = Fixture.Behaviors
                .OfType<ThrowingRecursionBehavior>()
                .ToList();

            foreach (var behavior in recursiveBehaviors)
            {
                Fixture.Behaviors.Remove(behavior);
            }

            Fixture.Behaviors.Add(new OmitOnRecursionBehavior(recursionDepth: 2));

            // Registra geradores úteis
            Fixture.Register(() => Guid.NewGuid());
            Fixture.Register(() => DateOnly.FromDateTime(DateTime.UtcNow.Date));
            Fixture.Register(() => TimeOnly.FromDateTime(DateTime.UtcNow));

            // Strings não nulas por padrão
            Fixture.Customize<string>(c => c.FromFactory(() => Guid.NewGuid().ToString("N")));
        }

        public IFixture Fixture { get; }

        /// <summary>
        /// Token de cancelamento padrão para operações assíncronas em testes.
        /// </summary>
        public CancellationToken Ct => _cts.Token;

        /// <summary>
        /// Atalho para criar instâncias com o AutoFixture.
        /// </summary>
        public T Create<T>() => Fixture.Create<T>();

        /// <summary>
        /// Permite customização adicional do AutoFixture em cenários específicos.
        /// </summary>
        public IFixture Customize(Action<IFixture> setup)
        {
            setup?.Invoke(Fixture);
            return Fixture;
        }

        public void Dispose()
        {
            _cts.Cancel();
            _cts.Dispose();
        }
    }
}