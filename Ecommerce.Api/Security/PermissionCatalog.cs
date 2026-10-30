using System.Collections.Concurrent;

namespace Ecommerce.Api.Security;

public sealed record PermissionDefinition(string Name, string Description);

public static class PermissionCatalog
{
    private static readonly ConcurrentDictionary<string, PermissionDefinition> _permissions = new(StringComparer.OrdinalIgnoreCase);

    static PermissionCatalog()
    {
        Register("products:read", "Read product catalog");
        Register("wallet:read", "Read wallet information");
        Register("orders:create", "Create purchase orders");
    }

    public static IReadOnlyList<PermissionDefinition> GetAll() =>
        _permissions.Values.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ToList();

    public static bool Register(string name, string? description = null)
    {
        if (string.IsNullOrWhiteSpace(name))
            return false;

        var normalized = name.Trim();
        _permissions[normalized] = new PermissionDefinition(normalized, description ?? "Custom permission");
        return true;
    }

    public static bool IsKnown(string? permission)
    {
        if (string.IsNullOrWhiteSpace(permission))
            return false;

        return _permissions.ContainsKey(permission.Trim());
    }

    public static HashSet<string> Normalize(IEnumerable<string>? permissions)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        if (permissions is null)
            return result;

        foreach (var permission in permissions)
        {
            if (string.IsNullOrWhiteSpace(permission))
                continue;

            var normalized = permission.Trim();
            if (IsKnown(normalized))
                result.Add(normalized);
        }

        return result;
    }
}
