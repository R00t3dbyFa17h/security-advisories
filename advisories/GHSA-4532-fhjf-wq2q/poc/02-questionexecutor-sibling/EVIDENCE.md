# QuestionExecutor sensitivity-boundary oracle — runtime PoC (sibling of MSRC Case 159229)

**Status:** runtime-proven on the published NuGet `Microsoft.Agents.AI.Workflows.Declarative` **1.24.0** (the release that fixed GHSA-9f26-7mqc-9vc4), net10.0, fully local, fabricated secret, no network.
**Relationship to Case 159229:** same root cause as the submitted `ConditionGroupExecutor` bug — an executor reads an attacker-authored expression via `Evaluator.GetValue(...).Value` and uses it for control flow **without** `GetNonSensitiveValue`/`ThrowIfSensitive`. This instance launders through `QuestionExecutor`. Provided as fix-completeness evidence for the Oct-14 completeness note; **not** a separate submission.

## Channel
`ObjectModel/QuestionExecutor.cs`
- line 52 `bool proceed = this.Evaluator.GetValue(this.Model.AlwaysPrompt).Value;`
- line 162 `long repeatCount = this.Evaluator.GetValue(this.Model.RepeatCount).Value;`  ← exercised by this PoC

Both read the evaluated value and discard `EvaluationResult.Sensitivity`. `WorkflowExpressionEngine.Evaluate` preserves the Sensitive tag (it does not strip or throw), and `GetNonSensitiveValue` (`Interpreter/DeclarativeActionExecutor.cs:158`) is the guard that would throw `DeclarativeActionException` on `SensitivityLevel.Sensitive` — it is never called here.

## Oracle mechanism (no secret value ever emitted)
`AlwaysPrompt: true`, `RepeatCount: =If(<predicate over Env.API_SECRET>, 0, 9)`:
- predicate **TRUE**  → `repeatCount = 0` → `PromptAsync(actualCount:0)` hits `0 >= 0` → emits the plain literal `DefaultValueResponse` ("QORACLE_HIT") as a `MessageActivityEvent`.
- predicate **FALSE** → `repeatCount = 9` → `0 >= 9` false → external-input branch, no literal emitted.

The emitted string is a fixed literal; the protected value only steers which branch runs. Iterating `=Mid(Env.API_SECRET, i, 1) = "c"` over positions/charset recovers the whole secret one bit at a time.

## Captured result (`captured-output.txt`)
```
== CONTROL: direct secret to sink (expect BLOCKED) ==
  outcome=BLOCKED ... DeclarativeActionException: Cannot send sensitive activity text: a.
== ORACLE validity ==
  predicate StartsWith(secret,"sk_live")  [TRUE]  -> emitted=QORACLE_HIT  => oracle bit = 1
  predicate StartsWith(secret,"xx")       [FALSE] -> emitted=<none>       => oracle bit = 0
== FULL SECRET RECOVERY via =Mid(Env.API_SECRET,i,1)="c" oracle ==
  recovered = "sk_live_SECRETBIT"
  actual    = "sk_live_SECRETBIT"
  match     = True
```
- **Control** proves the GHSA-9f26 boundary is active and the value is genuinely Sensitive-tagged (direct emission throws).
- **Validity** proves the observable literal tracks a secret-dependent predicate.
- **Recovery** proves full plaintext disclosure of the protected Env value via the unguarded `QuestionExecutor` control-flow read, with the secret never placed in any emitted string.

## Attacker model
Identical to Case 159229 / GHSA-9f26: a host exposes a secret to the workflow Env scope via `AllowedEnvironmentVariables` (+ process fallback) and runs a less-trusted declarative workflow definition that can reach an observable channel.

## Run
```
PATH="$HOME/.dotnet:$PATH" dotnet run -c Release
```
`QOracle.csproj` targets net10.0 and references the published 1.24.0 package. The 10-second `CancellationTokenSource` in `Run` only bounds the predicate-false external-input wait during testing; it does not affect the control or the true-branch emission.
