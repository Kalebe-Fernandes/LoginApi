using AuthAPI.Application.DTOs;
using FluentValidation;

namespace AuthAPI.Application.Validators
{
    public sealed class ConfirmEmailRequestValidator : AbstractValidator<ConfirmEmailRequest>
    {
        public ConfirmEmailRequestValidator()
        {
            RuleFor(x => x.UserId)
                .NotEmpty();

            RuleFor(x => x.Token)
                .NotEmpty();
        }
    }
}