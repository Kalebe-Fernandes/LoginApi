using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Moq.Language.Flow;

namespace AuthAPI.Tests.Tests.Shared
{
    public static class MockExtensions
    {
        /// <summary>
        /// Verifica se um log com o nível especificado e mensagem compatível foi emitido.
        /// Exemplo:
        /// loggerMock.VerifyLog(LogLevel.Error, msg => msg.Contains("erro"), Times.Once());
        /// </summary>
        public static void VerifyLog<T>(
            this Mock<ILogger<T>> logger,
            LogLevel level,
            Func<string, bool> messagePredicate,
            Times times)
        {
            logger.Verify(
                x => x.Log(
                    level,
                    It.IsAny<EventId>(),
                    It.Is<It.IsAnyType>((state, _) => messagePredicate(state != null ? state.ToString()! : string.Empty)),
                    It.IsAny<Exception>(),
                    (Func<It.IsAnyType, Exception?, string>)It.IsAny<object>()
                ),
                times);
        }

        /// <summary>
        /// Constrói um Mock<DbSet<T>> a partir de uma sequência (útil para repositórios simulados).
        /// </summary>
        public static Mock<DbSet<T>> BuildMockDbSet<T>(this IEnumerable<T> data) where T : class
        {
            var queryable = data.AsQueryable();

            var mockSet = new Mock<DbSet<T>>();

            mockSet.As<IQueryable<T>>().Setup(m => m.Provider).Returns(queryable.Provider);
            mockSet.As<IQueryable<T>>().Setup(m => m.Expression).Returns(queryable.Expression);
            mockSet.As<IQueryable<T>>().Setup(m => m.ElementType).Returns(queryable.ElementType);
            mockSet.As<IQueryable<T>>().Setup(m => m.GetEnumerator()).Returns(() => queryable.GetEnumerator());

            return mockSet;
        }

        /// <summary>
        /// Configura uma sequência de retornos para métodos assíncronos ReturnsAsync.
        /// Exemplo:
        /// mock.Setup(m => m.GetAsync()).ReturnsAsyncInOrder(v1, v2, v3);
        /// </summary>
        public static void ReturnsAsyncInOrder<TMock, TResult>(this ISetup<TMock, Task<TResult>> setup, params TResult[] results) where TMock : class
        {
            var queue = new Queue<TResult>(results);
            setup.ReturnsAsync(() => queue.Dequeue());
        }
    }
}