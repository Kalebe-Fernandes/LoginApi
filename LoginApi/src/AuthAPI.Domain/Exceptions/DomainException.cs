namespace AuthAPI.Domain.Exceptions
{
    public class DomainException : Exception
    {
        public string? Code { get; }

        public DomainException() { }

        public DomainException(string message) : base(message) { }

        public DomainException(string message, string? code) : base(message)
        {
            Code = code;
        }

        public DomainException(string message, Exception innerException) : base(message, innerException) { }

        public DomainException(string message, string? code, Exception innerException) : base(message, innerException)
        {
            Code = code;
        }
    }

    public class AuthenticationDomainException(string message) : DomainException(message)
    {
    }

    public class AuthorizationDomainException(string message) : DomainException(message)
    {
    }
}