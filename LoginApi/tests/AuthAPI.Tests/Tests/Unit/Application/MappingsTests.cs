using AutoMapper;
using AuthAPI.Application.DTOs;
using AuthAPI.Application.Handlers;
using AuthAPI.Application.Mappings;
using AuthAPI.Domain.Entities;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using AuthAPI.Tests.Tests.Shared;

namespace AuthAPI.Tests.Tests.Unit.Application
{
    public class MappingsTests : TestBase, IClassFixture<TestFixture>
    {
        private readonly IMapper _mapper;

        public MappingsTests(TestFixture fixture) : base(fixture)
        {
            var services = new ServiceCollection();
            services.AddAutoMapper(cfg => { }, typeof(AppMappingProfile).Assembly);
            var provider = services.BuildServiceProvider();
            _mapper = provider.GetRequiredService<IMapper>();
        }

        [Fact]
        public void Configuration_ShouldBeValid()
        {
            _mapper.ConfigurationProvider.AssertConfigurationIsValid();
        }

        [Fact]
        public void Should_Map_RegisterUserRequest_To_RegisterUserCommand()
        {
            var dto = new RegisterUserRequest(
                Email: "user@test.local",
                Password: "Abcdef12",
                NomeCompleto: "Test User",
                DataDeNascimento: DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-25))
            );

            var cmd = _mapper.Map<RegisterUserCommand>(dto);

            cmd.Email.Should().Be(dto.Email);
            cmd.Password.Should().Be(dto.Password);
            cmd.NomeCompleto.Should().Be(dto.NomeCompleto);
            cmd.DataDeNascimento.Should().Be(dto.DataDeNascimento);
        }

        [Fact]
        public void Should_Map_LoginRequest_To_LoginQuery_WithNull_IpAddress()
        {
            var dto = new LoginRequest("user@test.local", "P@ssw0rd!");
            var query = _mapper.Map<LoginQuery>(dto);

            query.Email.Should().Be(dto.Email);
            query.Password.Should().Be(dto.Password);
            query.IpAddress.Should().BeNull(); // configurado para ser definido externamente (controller)
        }

        [Fact]
        public void Should_Map_UserProfile_To_UserMeResponse_WithPlaceholders_And_MappedFields()
        {
            var userId = Guid.NewGuid();
            var profile = new UserProfile(userId, "Nome Completo", DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-30)));

            var dto = _mapper.Map<UserMeResponse>(profile);

            dto.UserId.Should().Be(userId);
            dto.NomeCompleto.Should().Be(profile.NomeCompleto);
            dto.DataDeNascimento.Should().Be(profile.DataDeNascimento);

            // Placeholders vindos do profile mapping (preenchidos externamente em fluxo real)
            dto.Email.Should().BeEmpty();
            dto.Roles.Should().BeEmpty();
        }

        [Fact]
        public void ReverseMap_NotConfigured_ShouldThrow_WhenAttemptingNonexistent_Map()
        {
            var cmd = new RegisterUserCommand("u@test.local", "Abcdef12", "Nome", DateOnly.FromDateTime(DateTime.UtcNow.AddYears(-20)));

            Action act = () => _mapper.Map<RegisterUserRequest>(cmd);

            act.Should().Throw<AutoMapperMappingException>();
        }
    }
}