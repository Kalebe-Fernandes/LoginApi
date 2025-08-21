using System;
using System.Collections.Generic;

namespace AuthAPI.Application.DTOs
{
    // Requisições
    public record RegisterUserRequest(
        string Email,
        string Password,
        string NomeCompleto,
        DateOnly DataDeNascimento
    );
}