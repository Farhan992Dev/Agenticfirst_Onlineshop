using System.Security.Claims;
using System.Text.Encodings.Web;
using Ecommerce.Core.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Ecommerce.Api.Security;

public static class ApiKeyAuthenticationDefaults
{
    public const string AuthenticationScheme = "ApiKey";
    public const string HeaderName = "X-API-Key";
}

public sealed class ApiKeyAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly AgentApiKeyService _apiKeyService;

    public ApiKeyAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        AgentApiKeyService apiKeyService)
        : base(options, logger, encoder, clock)
    {
        _apiKeyService = apiKeyService;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var token = GetTokenFromRequest();
        if (string.IsNullOrWhiteSpace(token))
        {
            return AuthenticateResult.NoResult();
        }

        var agent = await AgentRegistry.TryAuthenticateAsync(token, Request.HttpContext.RequestServices);
        if (agent is not null)
        {
            var principal = BuildPrincipal(agent);
            var ticket = new AuthenticationTicket(principal, ApiKeyAuthenticationDefaults.AuthenticationScheme);
            Request.HttpContext.Items["AgentIdentity"] = agent;
            return AuthenticateResult.Success(ticket);
        }

        var validation = await _apiKeyService.ValidateAsync(token);
        if (!validation.IsValid)
        {
            return AuthenticateResult.Fail(validation.Message);
        }

        var mappedIdentity = new AgentIdentity(
            AgentId: validation.KeyId,
            ClientName: validation.Name,
            AssignedUserId: validation.UserId,
            Permissions: validation.Permissions.ToHashSet(StringComparer.Ordinal));

        var apiKeyPrincipal = BuildPrincipal(mappedIdentity, validation.UserId, validation.KeyId);
        var apiKeyTicket = new AuthenticationTicket(apiKeyPrincipal, ApiKeyAuthenticationDefaults.AuthenticationScheme);

        Request.HttpContext.Items["AgentIdentity"] = mappedIdentity;
        Request.HttpContext.Items["MappedUserId"] = validation.UserId;
        return AuthenticateResult.Success(apiKeyTicket);
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        await Response.WriteAsJsonAsync(new
        {
            error = "Authentication Failed",
            message = "Invalid or missing Authorization header. Use Bearer <token>, ApiKey <key>, or X-API-Key: <key>."
        });
    }

    private string? GetTokenFromRequest()
    {
        var apiKeyHeader = Request.Headers[ApiKeyAuthenticationDefaults.HeaderName].ToString();
        if (!string.IsNullOrWhiteSpace(apiKeyHeader))
        {
            return apiKeyHeader.Trim();
        }

        var authHeader = Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authHeader))
        {
            return null;
        }

        if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return authHeader["Bearer ".Length..].Trim();
        }

        if (authHeader.StartsWith("ApiKey ", StringComparison.OrdinalIgnoreCase))
        {
            return authHeader["ApiKey ".Length..].Trim();
        }

        return authHeader.Trim();
    }

    private static ClaimsPrincipal BuildPrincipal(AgentIdentity agent, string? mappedUserId = null, string? keyId = null)
    {
        var identity = new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, mappedUserId ?? agent.AssignedUserId),
            new Claim(ClaimTypes.Name, agent.ClientName),
            new Claim("agent_id", agent.AgentId),
            new Claim("agent_name", agent.ClientName),
            new Claim("mapped_user_id", mappedUserId ?? agent.AssignedUserId),
            new Claim("assigned_user_id", agent.AssignedUserId),
            new Claim("permissions", string.Join(';', agent.Permissions.OrderBy(x => x)))
        ], ApiKeyAuthenticationDefaults.AuthenticationScheme);

        if (!string.IsNullOrWhiteSpace(keyId))
        {
            identity.AddClaim(new Claim("agent_key_id", keyId));
        }

        foreach (var permission in agent.Permissions)
        {
            identity.AddClaim(new Claim("permission", permission));
        }

        return new ClaimsPrincipal(identity);
    }
}
