namespace AuthAPI.Application.DTOs
{
    public record UserMeResponse(
        Guid UserId,
        string Email,
        string NomeCompleto,
        DateOnly? DataDeNascimento,
        IEnumerable<string> Roles
    );
}