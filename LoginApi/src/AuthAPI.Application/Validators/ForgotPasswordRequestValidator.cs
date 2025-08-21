using AuthAPI.Application.DTOs;
using FluentValidation;

namespace AuthAPI.Application.Validators
{
    public sealed class ForgotPasswordRequestValidator : AbstractValidator<ForgotPasswordRequest>
    {
        public ForgotPasswordRequestValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty()
                .EmailAddress();
        }
    }
}