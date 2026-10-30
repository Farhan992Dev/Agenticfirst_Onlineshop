using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json;

namespace Ecommerce.Api.Models;

public class AgentApiKey
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string UserId { get; set; } = string.Empty;
    public ApplicationUser? User { get; set; }

    public string Name { get; set; } = string.Empty;
    public string Prefix { get; set; } = string.Empty;
    public string KeyHash { get; set; } = string.Empty;
    public string PermissionsJson { get; set; } = "[]";

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime? ExpiresUtc { get; set; }
    public bool IsRevoked { get; set; }
    public DateTime? LastUsedUtc { get; set; }
    [NotMapped]
    public HashSet<string> Permissions
    {
        get => string.IsNullOrWhiteSpace(PermissionsJson)
            ? new HashSet<string>(StringComparer.Ordinal)
            : JsonSerializer.Deserialize<HashSet<string>>(PermissionsJson) ?? new HashSet<string>(StringComparer.Ordinal);
        set => PermissionsJson = JsonSerializer.Serialize(value ?? new HashSet<string>(StringComparer.Ordinal));
    }
}
