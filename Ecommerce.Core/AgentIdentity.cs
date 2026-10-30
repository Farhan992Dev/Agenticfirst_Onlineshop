namespace Ecommerce.Core.Security;

public sealed record AgentIdentity(
    string AgentId,
    string ClientName,
    string AssignedUserId, // Data-Level Authorization: bound user account
    IReadOnlySet<string> Permissions // Action-Level Authorization
);

public static class AgentRegistry
{
    // Pre-registered secure agents with specific permissions and bound user contexts
    private static readonly Dictionary<string, AgentIdentity> Tokens = new(StringComparer.Ordinal)
    {
        ["agent_secret_token_alpha_2026"] = new AgentIdentity(
            AgentId: "AGENT-ALPHA",
            ClientName: "Primary Copilot Shopping Assistant",
            AssignedUserId: "USR-AGENT-01",
            Permissions: new HashSet<string> { "products:read", "wallet:read", "orders:create" }
        ),
        ["agent_secret_token_readonly_2026"] = new AgentIdentity(
            AgentId: "AGENT-BETA",
            ClientName: "Audit & Support Bot",
            AssignedUserId: "USR-AUDIT-02",
            Permissions: new HashSet<string> { "products:read" }
        )
    };

    public static bool TryAuthenticate(string? token, out AgentIdentity? identity)
    {
        identity = null;
        if (string.IsNullOrWhiteSpace(token)) return false;
        return Tokens.TryGetValue(token.Trim(), out identity);
    }

    public static Task<AgentIdentity?> TryAuthenticateAsync(string? token, IServiceProvider services)
    {
        if (string.IsNullOrWhiteSpace(token))
            return Task.FromResult<AgentIdentity?>(null);

        return Task.FromResult(Tokens.TryGetValue(token.Trim(), out var identity) ? identity : null);
    }
}