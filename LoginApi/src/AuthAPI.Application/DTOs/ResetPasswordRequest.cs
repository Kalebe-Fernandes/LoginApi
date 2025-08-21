namespace AuthAPI.Application.DTOs
{
    public record ResetPasswordRequest(
        string UserId,
        string Token,
        string NewPassword
    );
}