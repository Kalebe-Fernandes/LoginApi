namespace AuthAPI.Application.Interfaces
{
    public interface IUnitOfWork
    {
        IUserRepository Users { get; }

        Task BeginAsync(CancellationToken ct);
        Task CommitAsync(CancellationToken ct);
        Task RollbackAsync(CancellationToken ct);
        Task<int> SaveChangesAsync(CancellationToken ct);
    }
}