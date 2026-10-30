using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Ecommerce.Api.Data;
using Ecommerce.Api.Models;
using Ecommerce.Api.Security;
using Ecommerce.Core.Engine;
using Ecommerce.Core.Mcp;
using Ecommerce.Core.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

builder.Services.AddIdentityApiEndpoints<ApplicationUser>(options =>
{
    options.SignIn.RequireConfirmedAccount = false;
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 6;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = false;
})
.AddRoles<IdentityRole>()
.AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = "MultiAuth";
        options.DefaultChallengeScheme = "MultiAuth";
        options.DefaultScheme = "MultiAuth";
    })
    .AddPolicyScheme("MultiAuth", "Authentication fallback", options =>
    {
        options.ForwardDefaultSelector = context =>
        {
            var authHeader = context.Request.Headers.Authorization.ToString();
            var apiKeyHeader = context.Request.Headers[ApiKeyAuthenticationDefaults.HeaderName].ToString();

            if (!string.IsNullOrWhiteSpace(apiKeyHeader))
                return ApiKeyAuthenticationDefaults.AuthenticationScheme;

            if (!string.IsNullOrWhiteSpace(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                return "Bearer";

            if (!string.IsNullOrWhiteSpace(authHeader) && authHeader.StartsWith("ApiKey ", StringComparison.OrdinalIgnoreCase))
                return ApiKeyAuthenticationDefaults.AuthenticationScheme;

            return ApiKeyAuthenticationDefaults.AuthenticationScheme;
        };
    })
    .AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(
        ApiKeyAuthenticationDefaults.AuthenticationScheme,
        _ => { });
   

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ApiKeyOnly", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireAssertion(context =>
            context.User.HasClaim(c => c.Type == "agent_key_id") ||
            context.User.HasClaim(c => c.Type == "agent_id"));
    });

    options.AddPolicy("UserOnly", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireAssertion(context =>
            !context.User.HasClaim(c => c.Type == "agent_key_id") &&
            !context.User.HasClaim(c => c.Type == "agent_id"));
    });
});

builder.Services.AddScoped<AgentApiKeyService>();
builder.Services.AddSingleton<ICommerceEngine, CommerceEngine>();
builder.Services.AddSingleton<McpRouter>();
builder.Services.AddSingleton<SseSessionManager>();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new()
    {
        Title = "Secure Agent-First E-Commerce & MCP API",
        Version = "v4.0",
        Description = "Fully secured with Authentication (Bearer Tokens), Action Authorization (RBAC Scopes), and Data Authorization (Context Binding & IDOR Prevention)."
    });

    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Enter JWT bearer token or paste a standard Bearer token here."
    });

    c.AddSecurityDefinition("ApiKey", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Name = "X-API-Key",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Enter a generated agent API key here."
    });

    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });

    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "ApiKey"
                }
            },
            Array.Empty<string>()
        }
    });
});

builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    db.Database.Migrate();
}

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
app.UseSwagger();
app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "Secure Ecommerce API v4.0"));

app.MapGet("/", () => Results.Ok(new
{
    Service = "Secure Agent-First E-Commerce Platform (v4.0)",
    Status = "Online & Secured",
    Authentication = "Bearer token for agent endpoints; Identity for user accounts; API key for mapped agent access",
    TestTokens = new[]
    {
        "agent_secret_token_alpha_2026 (Legacy sample token)",
        "agent_secret_token_readonly_2026 (Legacy sample token)"
    },
    Endpoints = new[] { "POST /mcp", "GET /mcp/sse", "GET /api/products", "GET /api/wallets/{userId}", "POST /register", "POST /login", "POST /logout", "POST /api/agent-keys/create", "POST /api/agent-keys/validate" }
}));

app.MapGroup("/").MapIdentityApi<ApplicationUser>();

app.MapPost("/api/agent-keys/create", async (CreateAgentApiKeyRequest request, UserManager<ApplicationUser> userManager, AgentApiKeyService keyService, HttpContext httpContext) =>
{
    var user = await userManager.GetUserAsync(httpContext.User);
    if (user is null)
        return Results.Unauthorized();

    var key = keyService.CreateKeyForUser(user.Id, request.Name, request.ExpiresInDays, request.Permissions);

    return Results.Ok(new
    {
        apiKey = key.ApiKey,
        keyId = key.KeyId,
        prefix = key.Prefix,
        userId = user.Id,
        userEmail = user.Email,
        expiresUtc = key.ExpiresUtc,
        createdUtc = key.CreatedUtc,
        permissions = key.Permissions
    });
}).RequireAuthorization("UserOnly");

app.MapPost("/api/agent-keys/validate", async (ValidateAgentApiKeyRequest request, AgentApiKeyService keyService) =>
{
    var result = await keyService.ValidateAsync(request.ApiKey);
    if (!result.IsValid)
        return Results.Json(new { valid = false, message = result.Message }, statusCode: 401);

    return Results.Ok(new
    {
        valid = true,
        userId = result.UserId,
        keyId = result.KeyId,
        prefix = result.Prefix,
        name = result.Name,
        expiresUtc = result.ExpiresUtc,
        permissions = result.Permissions
    });
}).AllowAnonymous();

app.MapGet("/api/permissions", () =>
{
    return Results.Ok(PermissionCatalog.GetAll().Select(x => new { x.Name, x.Description }));
}).RequireAuthorization("UserOnly");

app.MapPost("/api/permissions", (RegisterPermissionRequest request) =>
{
    var success = PermissionCatalog.Register(request.Name, request.Description);
    if (!success)
        return Results.BadRequest(new { error = "Permission name is required." });

    return Results.Ok(new { message = "Permission registered successfully.", permission = request.Name, description = request.Description });
}).RequireAuthorization("UserOnly");

app.MapGet("/api/agent-keys/me", async (UserManager<ApplicationUser> userManager, AgentApiKeyService keyService, HttpContext httpContext) =>
{
    var user = await userManager.GetUserAsync(httpContext.User);
    if (user is null)
        return Results.Unauthorized();

    var keys = await keyService.GetUserKeysAsync(user.Id);
    return Results.Ok(keys.Select(k => new
    {
        id = k.Id,
        name = k.Name,
        prefix = k.Prefix,
        createdUtc = k.CreatedUtc,
        expiresUtc = k.ExpiresUtc,
        isRevoked = k.IsRevoked,
        lastUsedUtc = k.LastUsedUtc,
        permissions = k.Permissions.OrderBy(x => x).ToList()
    }));
}).RequireAuthorization("UserOnly");

app.MapDelete("/api/agent-keys/{keyId}", async (string keyId, UserManager<ApplicationUser> userManager, AgentApiKeyService keyService, HttpContext httpContext) =>
{
    var user = await userManager.GetUserAsync(httpContext.User);
    if (user is null)
        return Results.Unauthorized();

    var deleted = await keyService.DeleteUserKeyAsync(user.Id, keyId);
    if (!deleted)
        return Results.NotFound(new { error = "API key not found for this user." });

    return Results.Ok(new { message = "API key deleted successfully." });
}).RequireAuthorization("UserOnly");

// ============================================================================
// MCP ENDPOINTS (Authenticated & Authorized via McpRouter)
// ============================================================================
app.MapPost("/mcp", async (HttpContext ctx, McpRouter router) =>
{
    var identity = ctx.Items["AgentIdentity"] as AgentIdentity
        ?? throw new InvalidOperationException("Identity missing from authenticated context.");

    var request = await JsonSerializer.DeserializeAsync<JsonRpcRequest>(ctx.Request.Body, McpRouter.JsonOptions);
    if (request is null) return Results.BadRequest(new { error = "Invalid JSON-RPC payload" });

    var response = router.HandleRequest(request, identity);
    if (response is null) return Results.Accepted();

    return Results.Json(response, McpRouter.JsonOptions);
}).RequireAuthorization("ApiKeyOnly", "UserOnly");

// ============================================================================
// SECURE REST API ENDPOINTS (Action & Data Authorization enforced)
// ============================================================================
app.MapGet("/api/products", ([FromQuery] string? query, [FromQuery] string? category, [FromQuery] decimal? maxPrice, HttpContext ctx, ICommerceEngine engine) =>
{
    var identity = (AgentIdentity)ctx.Items["AgentIdentity"]!;
    if (!identity.Permissions.Contains("products:read"))
        return Results.Json(new { error = "Forbidden: Missing 'products:read' scope" }, statusCode: 403);

    return Results.Ok(engine.SearchProducts(query, category, maxPrice));
}).RequireAuthorization("ApiKeyOnly", "UserOnly");

app.MapGet("/api/wallets/{userId}", (string userId, HttpContext ctx, ICommerceEngine engine) =>
{
    var identity = (AgentIdentity)ctx.Items["AgentIdentity"]!;
    if (!identity.Permissions.Contains("wallet:read"))
        return Results.Json(new { error = "Forbidden: Missing 'wallet:read' scope" }, statusCode: 403);

    // Data-Level Authorization: IDOR Prevention
    if (!userId.Equals(identity.AssignedUserId, StringComparison.OrdinalIgnoreCase))
        return Results.Json(new { error = $"Forbidden: Agent bound to '{identity.AssignedUserId}' cannot access wallet for '{userId}'." }, statusCode: 403);

    return Results.Ok(new { UserId = userId, Balance = engine.GetWalletBalance(userId), Currency = "USD" });
}).RequireAuthorization("ApiKeyOnly", "UserOnly");

app.MapPost("/api/orders", ([FromBody] CreateOrderRequest req, HttpContext ctx, ICommerceEngine engine) =>
{
    var identity = (AgentIdentity)ctx.Items["AgentIdentity"]!;
    if (!identity.Permissions.Contains("orders:create"))
        return Results.Json(new { error = "Forbidden: Missing 'orders:create' scope" }, statusCode: 403);

    var result = engine.PlaceOrder(identity.AssignedUserId, req.UserId, req.ProductId, req.Quantity, req.IdempotencyKey);
    if (!result.IsSuccess) return Results.BadRequest(new { result.ErrorCode, result.ErrorMessage });

    return Results.Ok(result.Data);
}).RequireAuthorization("ApiKeyOnly", "UserOnly");

app.Run();

public sealed record CreateOrderRequest(string UserId, string ProductId, int Quantity, string IdempotencyKey);
public sealed record CreateAgentApiKeyRequest(string Name, int? ExpiresInDays = null, List<string>? Permissions = null);
public sealed record ValidateAgentApiKeyRequest(string ApiKey);
public sealed record RegisterPermissionRequest(string Name, string? Description = null);

public sealed class AgentApiKeyService
{
    private readonly ApplicationDbContext _db;
    private const string Prefix = "ag_";

    public AgentApiKeyService(ApplicationDbContext db)
    {
        _db = db;
    }

    public CreatedAgentApiKey CreateKeyForUser(string userId, string name, int? expiresInDays, IEnumerable<string>? permissions = null)
    {
        var keyBytes = RandomNumberGenerator.GetBytes(32);
        var apiKey = $"{Prefix}{Convert.ToBase64String(keyBytes).Replace("+", "-").Replace("/", "_").TrimEnd('=')}";

        var prefix = apiKey[..12];
        var hash = ComputeHash(apiKey);
        var permissionSet = NormalizePermissions(permissions);

        var item = new AgentApiKey
        {
            UserId = userId,
            Name = string.IsNullOrWhiteSpace(name) ? "Default Agent Key" : name,
            Prefix = prefix,
            KeyHash = hash,
            Permissions = permissionSet,
            ExpiresUtc = expiresInDays.HasValue ? DateTime.UtcNow.AddDays(expiresInDays.Value) : null,
            CreatedUtc = DateTime.UtcNow,
            IsRevoked = false
        };

        _db.AgentApiKeys.Add(item);
        _db.SaveChanges();

        return new CreatedAgentApiKey
        {
            ApiKey = apiKey,
            KeyId = item.Id,
            Prefix = prefix,
            UserId = userId,
            Name = item.Name,
            ExpiresUtc = item.ExpiresUtc,
            CreatedUtc = item.CreatedUtc,
            Permissions = item.Permissions.OrderBy(x => x).ToList()
        };
    }

    public async Task<ValidationResult> ValidateAsync(string? apiKey)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            return ValidationResult.Invalid("API key was not provided.");

        var normalized = apiKey.Trim();
        var hash = ComputeHash(normalized);
        var dbKey = await _db.AgentApiKeys
            .Include(x => x.User)
            .FirstOrDefaultAsync(x => x.KeyHash == hash && !x.IsRevoked);

        if (dbKey is null)
            return ValidationResult.Invalid("API key is invalid.");

        if (dbKey.ExpiresUtc is DateTime expires && expires <= DateTime.UtcNow)
            return ValidationResult.Invalid("API key has expired.");

        dbKey.LastUsedUtc = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        return new ValidationResult
        {
            IsValid = true,
            UserId = dbKey.UserId,
            KeyId = dbKey.Id,
            Prefix = dbKey.Prefix,
            Name = dbKey.Name,
            ExpiresUtc = dbKey.ExpiresUtc,
            Permissions = dbKey.Permissions.OrderBy(x => x).ToList(),
            Message = "Valid"
        };
    }

    public async Task<List<AgentApiKey>> GetUserKeysAsync(string userId)
    {
        return await _db.AgentApiKeys
            .Where(x => x.UserId == userId)
            .OrderByDescending(x => x.CreatedUtc)
            .ToListAsync();
    }

    public async Task<bool> DeleteUserKeyAsync(string userId, string keyId)
    {
        var key = await _db.AgentApiKeys
            .FirstOrDefaultAsync(x => x.Id == keyId && x.UserId == userId);

        if (key is null)
            return false;

        _db.AgentApiKeys.Remove(key);
        await _db.SaveChangesAsync();
        return true;
    }

    private static HashSet<string> NormalizePermissions(IEnumerable<string>? permissions)
    {
        return PermissionCatalog.Normalize(permissions);
    }

    private static string ComputeHash(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes);
    }
}

public sealed class CreatedAgentApiKey
{
    public string ApiKey { get; set; } = string.Empty;
    public string KeyId { get; set; } = string.Empty;
    public string Prefix { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? UserEmail { get; set; }
    public DateTime? ExpiresUtc { get; set; }
    public DateTime CreatedUtc { get; set; }
    public IReadOnlyList<string> Permissions { get; set; } = Array.Empty<string>();
}

public sealed class ValidationResult
{
    public bool IsValid { get; set; }
    public string Message { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string KeyId { get; set; } = string.Empty;
    public string Prefix { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public DateTime? ExpiresUtc { get; set; }
    public IReadOnlyList<string> Permissions { get; set; } = Array.Empty<string>();

    public static ValidationResult Invalid(string message) => new() { IsValid = false, Message = message };
}

public sealed class SseSessionManager
{
    private readonly ConcurrentDictionary<string, Channel<string>> _sessions = new();
    public Channel<string> CreateSession(string id) { var c = Channel.CreateUnbounded<string>(); _sessions[id] = c; return c; }
    public bool TryGetSession(string id, out Channel<string>? c) => _sessions.TryGetValue(id, out c);
    public void RemoveSession(string id) { if (_sessions.TryRemove(id, out var c)) c.Writer.TryComplete(); }
}