using System.Text.Json;
using Ecommerce.Core.Engine;
using Ecommerce.Core.Security;

namespace Ecommerce.Core.Mcp;

public sealed class McpRouter
{
    private readonly ICommerceEngine _engine;
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    public McpRouter(ICommerceEngine engine)
    {
        _engine = engine;
    }

    public JsonRpcResponse? HandleRequest(JsonRpcRequest request, AgentIdentity identity)
    {
        if (request.Id is null || request.Id.Value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        try
        {
            return request.Method switch
            {
                "initialize" => HandleInitialize(request),
                "ping" => new JsonRpcResponse("2.0", request.Id, new { }),
                "tools/list" => HandleToolsList(request, identity),
                "tools/call" => HandleToolCall(request, identity),
                "resources/list" => HandleResourcesList(request),
                "resources/read" => HandleResourceRead(request),
                "prompts/list" => HandlePromptsList(request),
                "prompts/get" => HandlePromptGet(request),
                _ => new JsonRpcResponse("2.0", request.Id, Error: new JsonRpcError(-32601, $"Method '{request.Method}' not found"))
            };
        }
        catch (Exception ex)
        {
            return new JsonRpcResponse("2.0", request.Id, Error: new JsonRpcError(-32603, "Internal MCP Server error", ex.Message));
        }
    }

    private static JsonRpcResponse HandleInitialize(JsonRpcRequest request)
    {
        var result = new
        {
            protocolVersion = "2024-11-05",
            capabilities = new
            {
                tools = new { listChanged = false },
                resources = new { subscribe = false, listChanged = false },
                prompts = new { listChanged = false }
            },
            serverInfo = new
            {
                name = "dotnet-ecommerce-secure-mcp",
                version = "4.0.0"
            }
        };

        return new JsonRpcResponse("2.0", request.Id, result);
    }

    public object GetToolsCatalog() => new object[]
    {
        new
        {
            name = "search_products",
            description = "Search store catalog by keyword, category, and maximum price.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    query = new { type = "string", description = "Search term" },
                    category = new { type = "string", description = "Category filter" },
                    maxPrice = new { type = "number", description = "Max price in USD" }
                }
            }
        },
        new
        {
            name = "get_product_details",
            description = "Get detailed information for a specific product ID.",
            inputSchema = new
            {
                type = "object",
                properties = new { productId = new { type = "string" } },
                required = new[] { "productId" }
            }
        },
        new
        {
            name = "get_wallet_balance",
            description = "Check the user's current wallet balance and ledger history.",
            inputSchema = new
            {
                type = "object",
                properties = new { userId = new { type = "string", description = "Optional. If omitted, uses agent's bound user." } }
            }
        },
        new
        {
            name = "place_order",
            description = "Atomically purchase a product. Requires 'orders:create' permission.",
            inputSchema = new
            {
                type = "object",
                properties = new
                {
                    userId = new { type = "string", description = "Target User ID" },
                    productId = new { type = "string", description = "Product ID" },
                    quantity = new { type = "integer", description = "Quantity" },
                    idempotencyKey = new { type = "string", description = "Unique Idempotency Key" }
                },
                required = new[] { "productId", "quantity", "idempotencyKey" }
            }
        },
        new
        {
            name = "get_order_status",
            description = "Retrieve order details and status.",
            inputSchema = new
            {
                type = "object",
                properties = new { orderId = new { type = "string" } },
                required = new[] { "orderId" }
            }
        }
    };

    private JsonRpcResponse HandleToolsList(JsonRpcRequest request, AgentIdentity identity)
    {
        // Action-Level Authorization: Filter tools based on agent permissions
        var allTools = (object[])GetToolsCatalog();
        var authorizedTools = allTools.Where(t =>
        {
            var name = t.GetType().GetProperty("name")?.GetValue(t)?.ToString();
            return name switch
            {
                "search_products" => identity.Permissions.Contains("products:read"),
                "get_product_details" => identity.Permissions.Contains("products:read"),
                "get_wallet_balance" => identity.Permissions.Contains("wallet:read"),
                "place_order" => identity.Permissions.Contains("orders:create"),
                "get_order_status" => identity.Permissions.Contains("orders:create") || identity.Permissions.Contains("wallet:read"),
                _ => false
            };
        }).ToArray();

        return new JsonRpcResponse("2.0", request.Id, new { tools = authorizedTools });
    }

    private JsonRpcResponse HandleToolCall(JsonRpcRequest request, AgentIdentity identity)
    {
        if (request.Params is null)
            return new JsonRpcResponse("2.0", request.Id, Error: new JsonRpcError(-32602, "Missing params"));

        var p = request.Params.Value;
        var toolName = p.GetProperty("name").GetString();
        var args = p.TryGetProperty("arguments", out var a) ? a : default;

        // ====================================================================
        // ACTION-LEVEL AUTHORIZATION (RBAC / Permission Check)
        // ====================================================================
        bool isAuthorized = toolName switch
        {
            "search_products" or "get_product_details" => identity.Permissions.Contains("products:read"),
            "get_wallet_balance" => identity.Permissions.Contains("wallet:read"),
            "place_order" => identity.Permissions.Contains("orders:create"),
            "get_order_status" => identity.Permissions.Contains("orders:create") || identity.Permissions.Contains("wallet:read"),
            _ => false
        };

        if (!isAuthorized)
        {
            return new JsonRpcResponse("2.0", request.Id, Error: new JsonRpcError(-32603, 
                $"Forbidden: Agent '{identity.AgentId}' lacks permission to execute tool '{toolName}'. Required scope missing."));
        }

        return toolName switch
        {
            "search_products" => ExecuteSearchProducts(request.Id, args),
            "get_product_details" => ExecuteGetProductDetails(request.Id, args),
            "get_wallet_balance" => ExecuteGetWalletBalance(request.Id, args, identity),
            "place_order" => ExecutePlaceOrder(request.Id, args, identity),
            "get_order_status" => ExecuteGetOrderStatus(request.Id, args),
            _ => new JsonRpcResponse("2.0", request.Id, Error: new JsonRpcError(-32602, $"Unknown tool: {toolName}"))
        };
    }

    private JsonRpcResponse ExecuteSearchProducts(JsonElement? id, JsonElement args)
    {
        string? query = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("query", out var q) ? q.GetString() : null;
        string? category = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("category", out var c) ? c.GetString() : null;
        decimal? maxPrice = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("maxPrice", out var mp) && mp.ValueKind == JsonValueKind.Number ? mp.GetDecimal() : null;

        return ToolSuccess(id, _engine.SearchProducts(query, category, maxPrice));
    }

    private JsonRpcResponse ExecuteGetProductDetails(JsonElement? id, JsonElement args)
    {
        var productId = args.GetProperty("productId").GetString() ?? "";
        var product = _engine.GetProduct(productId);
        if (product is null) return ToolError(id, $"Product '{productId}' not found.");
        return ToolSuccess(id, product);
    }

    private JsonRpcResponse ExecuteGetWalletBalance(JsonElement? id, JsonElement args, AgentIdentity identity)
    {
        // Data-Level Authorization: Context Binding
        string userId = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("userId", out var u) && !string.IsNullOrEmpty(u.GetString())
            ? u.GetString()!
            : identity.AssignedUserId;

        // Prevent cross-user data access if agent is restricted
        if (!userId.Equals(identity.AssignedUserId, StringComparison.OrdinalIgnoreCase))
        {
            return ToolError(id, $"Unauthorized Data Access: Agent '{identity.AgentId}' is bound to user '{identity.AssignedUserId}' and cannot query wallet for '{userId}'.");
        }

        var balance = _engine.GetWalletBalance(userId);
        var entries = _engine.GetLedgerEntries(userId);

        return ToolSuccess(id, new { userId, availableBalance = balance, currency = "USD", ledgerEntries = entries });
    }

    private JsonRpcResponse ExecutePlaceOrder(JsonElement? id, JsonElement args, AgentIdentity identity)
    {
        // Data-Level Authorization: Context Binding (Default to agent's bound user)
        string targetUserId = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("userId", out var u) && !string.IsNullOrEmpty(u.GetString())
            ? u.GetString()!
            : identity.AssignedUserId;

        var productId = args.GetProperty("productId").GetString() ?? "";
        var quantity = args.GetProperty("quantity").GetInt32();
        var idempotencyKey = args.GetProperty("idempotencyKey").GetString() ?? "";

        // Engine will strictly enforce that authenticated identity matches targetUserId (IDOR prevention)
        var result = _engine.PlaceOrder(identity.AssignedUserId, targetUserId, productId, quantity, idempotencyKey);
        if (!result.IsSuccess)
        {
            return ToolError(id, $"[{result.ErrorCode}] {result.ErrorMessage}");
        }

        return ToolSuccess(id, result.Data!);
    }

    private JsonRpcResponse ExecuteGetOrderStatus(JsonElement? id, JsonElement args)
    {
        var orderId = args.GetProperty("orderId").GetString() ?? "";
        var order = _engine.GetOrder(orderId);
        if (order is null) return ToolError(id, $"Order '{orderId}' not found.");
        return ToolSuccess(id, order);
    }

    private static JsonRpcResponse HandleResourcesList(JsonRpcRequest request)
    {
        var resources = new object[]
        {
            new { uri = "ecommerce://catalog/full", name = "Full Catalog", mimeType = "application/json" },
            new { uri = "ecommerce://policies/security", name = "Security & Authorization Guidelines", mimeType = "text/markdown" }
        };
        return new JsonRpcResponse("2.0", request.Id, new { resources });
    }

    private JsonRpcResponse HandleResourceRead(JsonRpcRequest request)
    {
        var uri = request.Params?.GetProperty("uri").GetString() ?? "";
        if (uri == "ecommerce://catalog/full")
        {
            var json = JsonSerializer.Serialize(_engine.SearchProducts(null, null, null), JsonOptions);
            return new JsonRpcResponse("2.0", request.Id, new { contents = new[] { new { uri, mimeType = "application/json", text = json } } });
        }
        if (uri == "ecommerce://policies/security")
        {
            var policy = "# Agent-First Security Policies\n1. Authentication: Bearer token required.\n2. Action Authorization: RBAC scopes enforced.\n3. Data Authorization: Context binding prevents IDOR.";
            return new JsonRpcResponse("2.0", request.Id, new { contents = new[] { new { uri, mimeType = "text/markdown", text = policy } } });
        }
        return new JsonRpcResponse("2.0", request.Id, Error: new JsonRpcError(-32602, "Resource not found"));
    }

    private static JsonRpcResponse HandlePromptsList(JsonRpcRequest request)
    {
        var prompts = new object[] { new { name = "secure_shopping_advisor", description = "Secure shopping prompt" } };
        return new JsonRpcResponse("2.0", request.Id, new { prompts });
    }

    private static JsonRpcResponse HandlePromptGet(JsonRpcRequest request)
    {
        return new JsonRpcResponse("2.0", request.Id, new
        {
            description = "Secure Shopping Advisor",
            messages = new[] { new { role = "user", content = new { type = "text", text = "Verify balance and purchase securely." } } }
        });
    }

    private static JsonRpcResponse ToolSuccess(JsonElement? id, object payload) =>
        new("2.0", id, new { content = new[] { new { type = "text", text = JsonSerializer.Serialize(payload, JsonOptions) } }, isError = false });

    private static JsonRpcResponse ToolError(JsonElement? id, string msg) =>
        new("2.0", id, new { content = new[] { new { type = "text", text = msg } }, isError = true });
}