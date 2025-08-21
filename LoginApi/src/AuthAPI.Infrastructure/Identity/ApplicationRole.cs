using System;
using Microsoft.AspNetCore.Identity;

namespace AuthAPI.Infrastructure.Identity
{
    // Role personalizada para possibilitar extensões futuras
    public class ApplicationRole : IdentityRole<Guid>
    {
        public ApplicationRole() : base() { }
        public ApplicationRole(string roleName) : base(roleName) { }
    }
}