namespace AuthAPI.Application.DTOs
{
    public record ConfirmEmailRequest(
        string UserId,
        string Token
    );
}