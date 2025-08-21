using AuthAPI.Application.DTOs;
using FluentValidation;
using System.Text.RegularExpressions;

namespace AuthAPI.Application.Validators
{
    public sealed class RegisterUserRequestValidator : AbstractValidator<RegisterUserRequest>
    {
        public RegisterUserRequestValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty().WithMessage("Email é obrigatório.")
                .EmailAddress().WithMessage("Email inválido.")
                .MaximumLength(254);

            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("Senha é obrigatória.")
                .MinimumLength(8).WithMessage("Senha deve ter pelo menos 8 caracteres.")
                .Must(ContainLetterAndDigit).WithMessage("Senha deve conter letras e números.");

            RuleFor(x => x.NomeCompleto)
                .NotEmpty().WithMessage("Nome completo é obrigatório.")
                .MaximumLength(200);

            RuleFor(x => x.DataDeNascimento)
                .LessThanOrEqualTo(_ => DateOnly.FromDateTime(DateTime.UtcNow))
                .WithMessage("Data de nascimento não pode ser futura.");
        }

        private static bool ContainLetterAndDigit(string password)
        {
            if (string.IsNullOrWhiteSpace(password)) return false;
            var hasLetter = Regex.IsMatch(password, "[A-Za-z]");
            var hasDigit = Regex.IsMatch(password, "[0-9]");
            return hasLetter && hasDigit;
        }
    }
}