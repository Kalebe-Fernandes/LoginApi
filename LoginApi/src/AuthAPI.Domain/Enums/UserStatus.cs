namespace AuthAPI.Domain.Enums
{
    public enum UserStatus
    {
        PendingEmailConfirmation = 0,
        Active = 1,
        Suspended = 2,
        Deleted = 3
    }
}