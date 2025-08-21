using System.Text;
using AuthAPI.Infrastructure.Configurations;
using AuthAPI.Infrastructure.Data;
using AuthAPI.Infrastructure.Identity;
using AuthAPI.Infrastructure.Repositories;
using AuthAPI.Infrastructure.Services;
using FluentValidation;
using FluentValidation.AspNetCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Versioning;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Identity;
using Serilog;
using AuthAPI.Application.Interfaces;
using AuthAPI.API.Middleware;

var builder = WebApplication.CreateBuilder(args);

// Serilog
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .CreateLogger();

builder.Host.UseSerilog();

// Options binding
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection(JwtOptions.SectionName));
builder.Services.Configure<SmtpOptions>(builder.Configuration.GetSection(SmtpOptions.SectionName));

// EF Core - SQL Server LocalDB
builder.Services.AddDbContext<AuthDbContext>(options =>
{
    var cs = builder.Configuration.GetConnectionString("DefaultConnection");
    options.UseSqlServer(cs, sql =>
    {
        // Histórico de migrations dentro do schema auth
        sql.MigrationsHistoryTable("__EFMigrationsHistory", "auth");
    });
});

// Identity
builder.Services
    .AddIdentityCore<ApplicationUser>(options =>
    {
        options.Password.RequireDigit = true;
        options.Password.RequireUppercase = false;
        options.Password.RequireLowercase = true;
        options.Password.RequireNonAlphanumeric = false;
        options.Password.RequiredLength = 8;

        options.User.RequireUniqueEmail = true;

        options.SignIn.RequireConfirmedEmail = true;
    })
    .AddRoles<ApplicationRole>()
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddTokenProvider<DataProtectorTokenProvider<ApplicationUser>>(TokenOptions.DefaultProvider);

// Authentication - JWT
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    var jwtSection = builder.Configuration.GetSection(JwtOptions.SectionName);
    var issuer = jwtSection["Issuer"] ?? string.Empty;
    var audience = jwtSection["Audience"] ?? string.Empty;
    var secret = jwtSection["SecretKey"] ?? string.Empty;
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(string.IsNullOrWhiteSpace(secret) ? "invalid-secret-placeholder-change-with-user-secrets____________________________________________________" : secret));

    var clockSkewSeconds = int.TryParse(jwtSection["ClockSkewSeconds"], out var skew) ? skew : 60;

    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = issuer,
        ValidateAudience = true,
        ValidAudience = audience,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = key,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(clockSkewSeconds),
        NameClaimType = "UserID"
    };
});

// Authorization
builder.Services.AddAuthorization();

// Controllers + FluentValidation
builder.Services.AddControllers()
    .AddJsonOptions(o =>
    {
        o.JsonSerializerOptions.PropertyNamingPolicy = null;
    });

builder.Services.AddFluentValidationAutoValidation();
builder.Services.AddValidatorsFromAssemblies(AppDomain.CurrentDomain.GetAssemblies());

// AutoMapper
builder.Services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

// API Versioning (via URL segment /api/v{version}/...)
builder.Services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(1, 0);
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.ReportApiVersions = true;
    options.ApiVersionReader = new UrlSegmentApiVersionReader();
});
builder.Services.AddVersionedApiExplorer(setup =>
{
    setup.GroupNameFormat = "'v'VVV";
    setup.SubstituteApiVersionInUrl = true;
});

// Swagger/OpenAPI
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// DI - Application/Infrastructure
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();
builder.Services.AddScoped<ITokenService, JwtTokenService>();
builder.Services.AddScoped<IEmailService, SmtpEmailService>();

// CORS (opcional - liberar tudo em dev)
builder.Services.AddCors(options =>
{
    options.AddPolicy("DevAllowAll", policy =>
    {
        policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod();
    });
});

var app = builder.Build();

// Seed roles (Admin, User) on startup
using (var scope = app.Services.CreateScope())
{
    var repo = scope.ServiceProvider.GetRequiredService<IUserRepository>();
    var ct = CancellationToken.None;
    repo.EnsureRoleExistsAsync("Admin", ct).GetAwaiter().GetResult();
    repo.EnsureRoleExistsAsync("User", ct).GetAwaiter().GetResult();
}

// Pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseCors("DevAllowAll");
}

app.UseSerilogRequestLogging();

// Global exception handler middleware (custom)
app.UseMiddleware<ExceptionHandlingMiddleware>();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

public partial class Program { }
