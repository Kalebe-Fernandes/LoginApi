using AutoMapper;
using AuthAPI.Application.DTOs;
using AuthAPI.Application.Handlers;
using AuthAPI.Domain.Entities;

namespace AuthAPI.Application.Mappings
{
    public class AppMappingProfile : Profile
    {
        public AppMappingProfile()
        {
            // DTOs -> Commands/Queries
            CreateMap<RegisterUserRequest, RegisterUserCommand>();
            CreateMap<LoginRequest, LoginQuery>()
                // IpAddress será definido no controller em tempo de execução
                .ForCtorParam("IpAddress", opt => opt.MapFrom(src => (string?)null));

            // Domain -> DTOs
            CreateMap<UserProfile, UserMeResponse>()
                .ForCtorParam("UserId", opt => opt.MapFrom(src => src.Id))
                .ForCtorParam("Email", opt => opt.MapFrom(_ => string.Empty)) // preenchido externamente
                .ForCtorParam("NomeCompleto", opt => opt.MapFrom(src => src.NomeCompleto))
                .ForCtorParam("DataDeNascimento", opt => opt.MapFrom(src => src.DataDeNascimento))
                .ForCtorParam("Roles", opt => opt.MapFrom(_ => new List<string>()));
        }
    }
}