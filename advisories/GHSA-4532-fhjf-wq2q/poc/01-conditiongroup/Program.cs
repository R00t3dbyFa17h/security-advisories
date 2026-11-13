// Security regression harness for the Workflows.Declarative protected-value boundary.
// Authorized MSRC OSS bounty research. All data here is fabricated and local; no network.
// The boundary (GHSA-9f26) is meant to block ANY flow of a value derived from a protected
// Env entry out to a sink. This harness checks three scenarios against the shipped 1.24.0 engine.
using System.Runtime.CompilerServices;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Agents.AI.Workflows.Declarative;
using Microsoft.Agents.AI.Workflows.Declarative.Events;
using Microsoft.Extensions.AI;

// Host exposes a protected config value to the workflow environment scope (engine marks it Sensitive).
Environment.SetEnvironmentVariable("API_SECRET", "sk_live_SECRETBIT");

const string Head = "kind: Workflow\ntrigger:\n  kind: OnConversationStart\n  id: w\n  actions:\n";

// Scenario A (expect BLOCK): use the protected value directly in a sink.
string directYaml = Head +
  "    - kind: SendActivity\n      id: a\n      activity: \"OUT={Env.API_SECRET}\"\n";

// Scenario B (expect BLOCK): use a value arithmetically derived from the protected value.
string derivedYaml = Head +
  "    - kind: SetVariable\n      id: s\n      variable: Local.C\n      value: =Left(Env.API_SECRET, 2)\n" +
  "    - kind: SendActivity\n      id: a\n      activity: \"OUT={Local.C}\"\n";

// Scenario C (boundary SHOULD block, same net flow): ConditionGroup branches on a predicate over the
// protected value; the taken branch writes a plain literal into a non-sensitive variable, which the
// sink then emits. Net effect: a secret-dependent value crosses the sink boundary.
string oracleYaml = Head +
  "    - kind: ConditionGroup\n      id: g\n      conditions:\n" +
  "        - id: c\n          condition: =StartsWith(Env.API_SECRET, \"sk_live\")\n          actions:\n" +
  "            - kind: SetVariable\n              id: s\n              variable: Local.Leak\n              value: =\"prefix_is_sk_live\"\n" +
  "      elseActions:\n" +
  "        - kind: SetVariable\n          id: s2\n          variable: Local.Leak\n          value: =\"prefix_other\"\n" +
  "    - kind: SendActivity\n      id: a\n      activity: \"OUT={Local.Leak}\"\n";

await Chain.RunAsync();
await Extract.RunAsync();
foreach (var (name, yaml, expect) in new[] {
    ("A direct", directYaml, "BLOCK"),
    ("B derived", derivedYaml, "BLOCK"),
    ("C condition-oracle", oracleYaml, "BLOCK"),
}) {
    var opts = new DeclarativeWorkflowOptions(new StubProvider())
    {
        AllowedEnvironmentVariables = new[] { "API_SECRET" },
        AllowProcessEnvironmentVariableFallback = true,
    };
    string? emitted = null; string? error = null;
    try {
        using var reader = new StringReader(yaml);
        var wf = DeclarativeWorkflowBuilder.Build<string>(reader, opts);
        await using var run = await InProcessExecution.RunStreamingAsync(wf, "go");
        await foreach (var ev in run.WatchStreamAsync()) {
            if (ev is MessageActivityEvent m) emitted = m.Message?.Trim();
            if (ev is WorkflowErrorEvent e) { var ex=e.Data as Exception; var sb=new System.Text.StringBuilder(); for(var x=ex;x!=null;x=x.InnerException) sb.Append(x.GetType().Name+": "+x.Message+" || "); error=sb.ToString(); break; }
        }
    } catch (Exception ex) { error = ex.Message; }

    string outcome = error is not null ? "BLOCKED" : "EMITTED";
    bool leaked = error is null && emitted is not null;
    string verdict = outcome == "BLOCKED" ? "boundary held"
                   : (leaked ? ">>> BOUNDARY BYPASSED (secret-dependent value reached sink)" : "emitted empty");
    Console.WriteLine($"[{name}] expect={expect} -> {outcome}  emitted={emitted ?? "<none>"}  {(error is null ? "" : "err=" + error)}  {verdict}");
}

sealed class StubProvider : ResponseAgentProvider
{
    public override Task<string> CreateConversationAsync(CancellationToken ct = default) => Task.FromResult("conv-1");
    public override Task<ChatMessage> CreateMessageAsync(string c, ChatMessage m, CancellationToken ct = default) => Task.FromResult(m);
    public override Task<ChatMessage> GetMessageAsync(string c, string id, CancellationToken ct = default) => Task.FromResult(new ChatMessage(ChatRole.User, string.Empty));
    public override async IAsyncEnumerable<AgentResponseUpdate> InvokeAgentAsync(string a, string? v, string? c, IEnumerable<ChatMessage>? m, IDictionary<string, object?>? i, [EnumeratorCancellation] CancellationToken ct = default) { yield break; await Task.CompletedTask; }
    public override async IAsyncEnumerable<ChatMessage> GetMessagesAsync(string c, int? l = null, string? a = null, string? b = null, bool n = false, [EnumeratorCancellation] CancellationToken ct = default) { yield break; await Task.CompletedTask; }
}
