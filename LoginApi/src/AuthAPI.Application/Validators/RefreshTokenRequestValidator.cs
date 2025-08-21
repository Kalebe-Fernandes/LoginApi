using AuthAPI.Application.DTOs;
using FluentValidation;

namespace AuthAPI.Application.Validators
{
    public sealed class RefreshTokenRequestValidator : AbstractValidator<RefreshTokenRequest>
    {
        public RefreshTokenRequestValidator()
        {
            RuleFor(x => x.RefreshToken)
                .NotEmpty().WithMessage("Refresh token é obrigatório.")
                .MaximumLength(2048);
        }
    }
}