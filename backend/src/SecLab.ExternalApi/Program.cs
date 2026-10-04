// Small "external" service. Trivial in the starter; the Testing step turns it into a contract-test provider.
var app = WebApplication.CreateBuilder(args).Build();
app.MapGet("/api/link-preview", (string url) => new { url, title = $"Preview of {url}", description = "Placeholder preview." });
app.Run();

public partial class Program;
