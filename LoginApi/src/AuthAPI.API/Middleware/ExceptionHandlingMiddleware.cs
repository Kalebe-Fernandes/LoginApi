using System.Text.Json;
using AuthAPI.Domain.Exceptions;
using Microsoft.AspNetCore.Mvc;

namespace AuthAPI.API.Middleware
{
    public sealed class ExceptionHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ExceptionHandlingMiddleware> _logger;

        public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (DomainException dex)
            {
                _logger.LogWarning(dex, "Erro de domínio: {Message}", dex.Message);
                await WriteProblem(context, StatusCodes.Status400BadRequest, "DomainError", dex.Message);
            }
            catch (UnauthorizedAccessException uex)
            {
                _logger.LogWarning(uex, "Não autorizado: {Message}", uex.Message);
                await WriteProblem(context, StatusCodes.Status401Unauthorized, "Unauthorized", "Acesso não autorizado.");
            }
            catch (KeyNotFoundException kex)
            {
                _logger.LogWarning(kex, "Não encontrado: {Message}", kex.Message);
                await WriteProblem(context, StatusCodes.Status404NotFound, "NotFound", kex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro inesperado");
                await WriteProblem(context, StatusCodes.Status500InternalServerError, "UnexpectedError", "Ocorreu um erro inesperado.");
            }
        }

        private static async Task WriteProblem(HttpContext context, int status, string type, string detail)
        {
            var problem = new ProblemDetails
            {
                Status = status,
                Title = ReasonPhrases(status),
                Type = type,
                Detail = detail,
                Instance = context.TraceIdentifier
            };

            context.Response.ContentType = "application/problem+json";
            context.Response.StatusCode = status;

            var opts = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
            await context.Response.WriteAsync(JsonSerializer.Serialize(problem, opts));
        }

        private static string ReasonPhrases(int statusCode) => statusCode switch
        {
            StatusCodes.Status400BadRequest => "Bad Request",
            StatusCodes.Status401Unauthorized => "Unauthorized",
            StatusCodes.Status403Forbidden => "Forbidden",
            StatusCodes.Status404NotFound => "Not Found",
            StatusCodes.Status409Conflict => "Conflict",
            StatusCodes.Status422UnprocessableEntity => "Unprocessable Entity",
            StatusCodes.Status500InternalServerError => "Internal Server Error",
            _ => "Error"
        };
    }
}