using System;
using System.Linq;
using AuthAPI.Application.DTOs;
using AuthAPI.Application.Validators;
using AuthAPI.Tests.Tests.Shared;
using FluentAssertions;
using FluentValidation.Results;

namespace AuthAPI.Tests.Tests.Unit.Application
{
    public class ValidatorsTests(TestFixture fixture) : TestBase(fixture), IClassFixture<TestFixture>
    {
        private static ValidationResult Validate(RegisterUserRequest request)
            => new RegisterUserRequestValidator().Validate(request);

        private static ValidationResult Validate(LoginRequest request)
            => new LoginRequestValidator().Validate(request);

        private static ValidationResult Validate(ConfirmEmailRequest request)
            => new ConfirmEmailRequestValidator().Validate(request);

        private static ValidationResult Validate(RefreshTokenRequest request)
            => new RefreshTokenRequestValidator().Validate(request);

        private static ValidationResult Validate(ResetPasswordRequest request)
            => new ResetPasswordRequestValidator().Validate(request);

        private static ValidationResult Validate(ForgotPasswordRequest request)
            => new ForgotPasswordRequestValidator().Validate(request);

        private static void ShouldHaveErrorFor(ValidationResult result, string property, string? containsMessage = null)
        {
            result.IsValid.Should().BeFalse("expected validation to fail for {0}", property);
            var propErrors = result.Errors.Where(e => e.PropertyName == property).ToList();
            propErrors.Should().NotBeEmpty($"expected error for property {property}");
            
            if (!string.IsNullOrWhiteSpace(containsMessage))
            {
                propErrors.Any(e => e.ErrorMessage.Contains(containsMessage!, StringComparison.OrdinalIgnoreCase))
                          .Should().BeTrue($"expected error message containing '{containsMessage}' for {property}");
            }
        }

        private static void ShouldNotHaveAnyErrors(ValidationResult result)
        {
            result.IsValid.Should().BeTrue(result.Errors.Count != 0 ? string.Join(" | ", result.Errors.Select(e => $"{e.PropertyName}: {e.ErrorMessage}")) : "expected valid result");
        }

        // RegisterUserRequestValidator
        [Fact]
        public void RegisterUser_Valid_ShouldPass()
        {
            var req = new RegisterUserRequest(
                Email: "user@domain..comlocal",
                Password: "Abcdef12",
                NomeCompleto: "Usuário Teste",
                DataDeNascimento: DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-20))
            );

            var result = Validate(req);
            ShouldNotHaveAnyErrors(result);
        }

        [Theory]
        [InlineData("")]
        [InlineData("invalid")]
        [InlineData("user@")]
        [InlineData("user@@test.local")]
        
        public void RegisterUser_Email_Invalid_ShouldHaveError(string email)
        {
            var req = new RegisterUserRequest(
                Email: email,
                Password: "Abcdef12",
                NomeCompleto: "Nome Completo",
                DataDeNascimento: DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-18))
            );

            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(RegisterUserRequest.Email));
        }

        [Fact]
        public void RegisterUser_Email_MaxLengthExceeded_ShouldHaveError()
        {
            var local = new string('a', 250);
            var email = $"{local}@t.co"; // length 255
            var req = new RegisterUserRequest(
                Email: email,
                Password: "Abcdef12",
                NomeCompleto: "Nome Completo",
                DataDeNascimento: DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-18))
            );

            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(RegisterUserRequest.Email));
        }

        [Fact]
        public void RegisterUser_Password_NoDigit_ShouldHaveError()
        {
            var req = new RegisterUserRequest(
                Email: "user@domain..comlocal",
                Password: "OnlyLetters",
                NomeCompleto: "Nome Completo",
                DataDeNascimento: DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-18))
            );

            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(RegisterUserRequest.Password), "letras e números");
        }

        [Fact]
        public void RegisterUser_Password_NoLetter_ShouldHaveError()
        {
            var req = new RegisterUserRequest(
                Email: "user@domain..comlocal",
                Password: "12345678",
                NomeCompleto: "Nome Completo",
                DataDeNascimento: DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-18))
            );

            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(RegisterUserRequest.Password), "letras e números");
        }

        [Fact]
        public void RegisterUser_Password_TooShort_ShouldHaveError()
        {
            var req = new RegisterUserRequest(
                Email: "user@domain..comlocal",
                Password: "Abc12",
                NomeCompleto: "Nome Completo",
                DataDeNascimento: DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-18))
            );

            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(RegisterUserRequest.Password));
        }

        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData("     ")]
        public void RegisterUser_NomeCompleto_EmptyOrWhitespace_ShouldHaveError(string nome)
        {
            var req = new RegisterUserRequest(
                Email: "user@domain..comlocal",
                Password: "Abcdef12",
                NomeCompleto: nome,
                DataDeNascimento: DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-18))
            );

            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(RegisterUserRequest.NomeCompleto));
        }

        [Fact]
        public void RegisterUser_NomeCompleto_MaxLengthExceeded_ShouldHaveError()
        {
            var req = new RegisterUserRequest(
                Email: "user@domain..comlocal",
                Password: "Abcdef12",
                NomeCompleto: new string('x', 201),
                DataDeNascimento: DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-18))
            );

            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(RegisterUserRequest.NomeCompleto));
        }

        [Fact]
        public void RegisterUser_DataDeNascimento_Future_ShouldHaveError()
        {
            var req = new RegisterUserRequest(
                Email: "user@domain..comlocal",
                Password: "Abcdef12",
                NomeCompleto: "Nome Completo",
                DataDeNascimento: DateOnly.FromDateTime(DateTime.UtcNow.AddDays(1))
            );

            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(RegisterUserRequest.DataDeNascimento));
        }

        [Fact]
        public void RegisterUser_DataDeNascimento_PastLongAgo_ShouldPass()
        {
            var req = new RegisterUserRequest(
                Email: "user@domain..comlocal",
                Password: "Abcdef12",
                NomeCompleto: "Nome Completo",
                DataDeNascimento: new DateOnly(1900, 1, 1)
            );

            var result = Validate(req);
            ShouldNotHaveAnyErrors(result);
        }

        // LoginRequestValidator

        [Fact]
        public void Login_Valid_ShouldPass()
        {
            var req = new LoginRequest("user@domain..comlocal", "P@ssw0rd");
            var result = Validate(req);
            ShouldNotHaveAnyErrors(result);
        }

        [Theory]
        [InlineData("")]
        [InlineData("invalid")]
        [InlineData("user@")]
        public void Login_Email_Invalid_ShouldHaveError(string email)
        {
            var req = new LoginRequest(email, "P@ssw0rd");
            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(LoginRequest.Email));
        }

        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        public void Login_Password_Empty_ShouldHaveError(string pwd)
        {
            var req = new LoginRequest("user@domain..comlocal", pwd);
            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(LoginRequest.Password));
        }

        // ConfirmEmailRequestValidator

        [Fact]
        public void ConfirmEmail_Valid_ShouldPass()
        {
            var req = new ConfirmEmailRequest(Guid.NewGuid().ToString(), "TOKEN");
            var result = Validate(req);
            ShouldNotHaveAnyErrors(result);
        }

        [Fact]
        public void ConfirmEmail_UserId_Empty_ShouldHaveError()
        {
            var req = new ConfirmEmailRequest("", "TOKEN");
            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(ConfirmEmailRequest.UserId));
        }

        [Fact]
        public void ConfirmEmail_Token_Empty_ShouldHaveError()
        {
            var req = new ConfirmEmailRequest(Guid.NewGuid().ToString(), "");
            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(ConfirmEmailRequest.Token));
        }

        // RefreshTokenRequestValidator

        [Fact]
        public void RefreshToken_Valid_ShouldPass()
        {
            var req = new RefreshTokenRequest($"{Guid.NewGuid()}.payload");
            var result = Validate(req);
            ShouldNotHaveAnyErrors(result);
        }

        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        public void RefreshToken_Empty_ShouldHaveError(string token)
        {
            var req = new RefreshTokenRequest(token);
            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(RefreshTokenRequest.RefreshToken));
        }

        [Fact]
        public void RefreshToken_TooLong_ShouldHaveError()
        {
            var big = new string('a', 2049);
            var req = new RefreshTokenRequest(big);
            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(RefreshTokenRequest.RefreshToken));
        }

        // ResetPasswordRequestValidator

        [Fact]
        public void ResetPassword_Valid_ShouldPass()
        {
            var req = new ResetPasswordRequest(Guid.NewGuid().ToString(), "TOKEN", "Abcdef12");
            var result = Validate(req);
            ShouldNotHaveAnyErrors(result);
        }

        [Fact]
        public void ResetPassword_MissingFields_ShouldHaveErrors()
        {
            var req = new ResetPasswordRequest("", "", "");
            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(ResetPasswordRequest.UserId));
            ShouldHaveErrorFor(result, nameof(ResetPasswordRequest.Token));
            ShouldHaveErrorFor(result, nameof(ResetPasswordRequest.NewPassword));
        }

        [Fact]
        public void ResetPassword_NewPassword_NoDigit_ShouldHaveError()
        {
            var req = new ResetPasswordRequest(Guid.NewGuid().ToString(), "TOKEN", "OnlyLetters");
            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(ResetPasswordRequest.NewPassword), "letras e números");
        }

        [Fact]
        public void ResetPassword_NewPassword_NoLetter_ShouldHaveError()
        {
            var req = new ResetPasswordRequest(Guid.NewGuid().ToString(), "TOKEN", "12345678");
            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(ResetPasswordRequest.NewPassword), "letras e números");
        }

        [Fact]
        public void ResetPassword_NewPassword_TooShort_ShouldHaveError()
        {
            var req = new ResetPasswordRequest(Guid.NewGuid().ToString(), "TOKEN", "Abc12");
            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(ResetPasswordRequest.NewPassword));
        }

        // ForgotPasswordRequestValidator

        [Fact]
        public void ForgotPassword_Valid_ShouldPass()
        {
            var req = new ForgotPasswordRequest("user@domain..comlocal");
            var result = Validate(req);
            ShouldNotHaveAnyErrors(result);
        }

        [Theory]
        [InlineData("")]
        [InlineData("invalid")]
        [InlineData("user@")]
        public void ForgotPassword_Email_Invalid_ShouldHaveError(string email)
        {
            var req = new ForgotPasswordRequest(email);
            var result = Validate(req);
            ShouldHaveErrorFor(result, nameof(ForgotPasswordRequest.Email));
        }
    }
}