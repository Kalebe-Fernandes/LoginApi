using AuthAPI.Application.Interfaces;
using AuthAPI.Infrastructure.Data;
using Microsoft.EntityFrameworkCore.Storage;

namespace AuthAPI.Infrastructure.Services
{
    public sealed class UnitOfWork(AuthDbContext dbContext, IUserRepository repository) : IUnitOfWork, IAsyncDisposable
    {
        private readonly AuthDbContext _dbContext = dbContext;
        private readonly IUserRepository _repository = repository;
        private IDbContextTransaction? _currentTransaction;

        public IUserRepository Users => _repository;

        public async Task BeginAsync(CancellationToken ct)
        {
            if (_currentTransaction is not null)
                return;

            _currentTransaction = await _dbContext.Database.BeginTransactionAsync(ct);
        }

        public async Task CommitAsync(CancellationToken ct)
        {
            if (_currentTransaction is null)
                return;

            await _dbContext.SaveChangesAsync(ct);
            await _currentTransaction.CommitAsync(ct);
            await _currentTransaction.DisposeAsync();
            _currentTransaction = null;
        }

        public async Task RollbackAsync(CancellationToken ct)
        {
            if (_currentTransaction is null)
                return;

            await _currentTransaction.RollbackAsync(ct);
            await _currentTransaction.DisposeAsync();
            _currentTransaction = null;
        }

        public Task<int> SaveChangesAsync(CancellationToken ct)
            => _dbContext.SaveChangesAsync(ct);

        public async ValueTask DisposeAsync()
        {
            if (_currentTransaction is not null)
            {
                await _currentTransaction.DisposeAsync();
                _currentTransaction = null;
            }
        }
    }
}