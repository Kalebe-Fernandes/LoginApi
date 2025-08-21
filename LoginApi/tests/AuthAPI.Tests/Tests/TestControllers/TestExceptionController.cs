using AuthAPI.Domain.Exceptions;
using Microsoft.AspNetCore.Mvc;

namespace AuthAPI.Tests.Tests.TestControllers
{
    [ApiController]
    [Route("__test/exception")]
    public class TestExceptionController : ControllerBase
    {
        [HttpGet("domain")]
        public IActionResult ThrowDomain() => throw new DomainException("Domain boom!");

        [HttpGet("unauthorized")]
        public IActionResult ThrowUnauthorized() => throw new UnauthorizedAccessException("Nope");

        [HttpGet("notfound")]
        public IActionResult ThrowNotFound() => throw new KeyNotFoundException("Missing");

        [HttpGet("generic")]
        public IActionResult ThrowGeneric() => throw new Exception("Kaboom");
    }
}