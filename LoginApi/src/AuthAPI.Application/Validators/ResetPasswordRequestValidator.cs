using AuthAPI.Application.DTOs;
using FluentValidation;
using System.Text.RegularExpressions;

namespace AuthAPI.Application.Validators
{
    public sealed class ResetPasswordRequestValidator : AbstractValidator<ResetPasswordRequest>
    {
        public ResetPasswordRequestValidator()
        {
            RuleFor(x => x.UserId)
                .NotEmpty();
            RuleFor(x => x.Token)
                .NotEmpty();
            RuleFor(x => x.NewPassword)
                .NotEmpty()
                .MinimumLength(8)
                .Must(ContainLetterAndDigit).WithMessage("Senha deve conter letras e números.");
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