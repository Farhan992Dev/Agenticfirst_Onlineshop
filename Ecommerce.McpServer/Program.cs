using System.Text;
using System.Text.Json;
using Ecommerce.Core.Engine;
using Ecommerce.Core.Mcp;
using Ecommerce.Core.Security;

Console.InputEncoding = Encoding.UTF8;
Console.OutputEncoding = Encoding.UTF8;

var engine = new CommerceEngine();
var router = new McpRouter(engine);
// Stdio uses alpha high-privilege identity by default
var identity = AgentRegistry.TryAuthenticate("agent_secret_token_alpha_2026", out var id) ? id! : throw new Exception("Identity error");

await Console.Error.WriteLineAsync("[Secure MCP Server] Started on stdio.");

string? line;
while ((line = await Console.In.ReadLineAsync()) is not null)
{
    if (string.IsNullOrWhiteSpace(line)) continue;
    try
    {
        var request = JsonSerializer.Deserialize<JsonRpcRequest>(line, McpRouter.JsonOptions);
        if (request is null) continue;
        var response = router.HandleRequest(request, identity);
        if (response is not null)
        {
            await Console.Out.WriteLineAsync(JsonSerializer.Serialize(response, McpRouter.JsonOptions));
            await Console.Out.FlushAsync();
        }
    }
    catch (Exception ex)
    {
        await Console.Error.WriteLineAsync($"[MCP Error] {ex.Message}");
    }
}
