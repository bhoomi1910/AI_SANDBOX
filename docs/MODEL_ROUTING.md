# MODEL_ROUTING.md

## 1. Policy

Free-model-first is mandatory. Never assume paid models are available. If there is
uncertainty about whether a model costs money, treat it as **unavailable** unless
explicitly confirmed free.

## 2. Verified Environment (audit, 09 Aug 2026)

Facts confirmed by inspecting this OpenCode environment — not guesses:

- `~/.config/opencode/opencode.jsonc` is an empty stub (`{ "$schema": ... }`).
- No `auth.json` / credentials / accounts found in any OpenCode config or data location.
- The OpenCode local database (`~/.local/share/opencode/opencode.db`) contains **exactly one
  configured model**: `big-pickle`, provider `opencode`. That is the model driving this
  session.
- No Ollama, Docker, or other model-serving tools are installed on this machine.

**Conclusion:** this is currently a **single-model environment**. The only available model is
`opencode/big-pickle`. There are no other providers, no authenticated accounts, and no local
LLM runtime.

## 3. Currently Available Models

| Model | Provider | Status | Notes |
|-------|----------|--------|-------|
| `big-pickle` | `opencode` | ✅ Available | The model running this session; use for all tasks until other models are confirmed. |

Because only one model is available, model-based task routing is **moot for now**: every task
is handled by `big-pickle`. Do **not** create sub-agents to "use different models" — there is
nothing to route to. This doc defines the *framework* to activate the moment more free models
are confirmed.

## 4. How New Models Get Added (and confirmed)

For each candidate model, one of these must be true before we rely on it:

1. **Confirmed by the user** as free (user is the authority on their accounts/subscriptions).
2. **Locally installed and free by construction** — e.g., an LLM pulled into **Ollama**
   (the project's intended local-AI runtime). Installing Ollama and pulling a model is
   itself a milestone in this project.

Candidate families for Ollama (documented as intended by AI_ENGINE.md, **not assumed
installed**): Qwen, DeepSeek, Llama, Mistral, CodeLlama. Each must be verified with
`ollama list` after installation before being relied on.

## 5. Routing Framework (to be applied once ≥2 models exist)

Intended roles, mapped to the strongest *confirmed-free* model available:

| Role | Task types | Preferred model tier |
|------|-----------|----------------------|
| ARCHITECT | architecture, security design, difficult debugging, complex backend | strongest available free model |
| CODER | feature implementation, API endpoints, React components | strong free model |
| REVIEWER | code/security review, regression detection | second capable free model |
| TESTER | unit/integration tests, bug reproduction | efficient free model |
| DOCUMENTATION | README, API docs, changelog | efficient model |
| SIMPLE TASKS | formatting, small fixes, repetitive edits | fastest free model |

With a single model, all roles collapse into one. Do not add agents for the sake of it.

## 6. Project-Side AI (Ollama) routing intent

The *application's* AI engine (separate from the OpenCode tooling) should follow the same
philosophy once Ollama is running:

- small/fast local model → classification, extraction, summarization, routine explanations
- stronger local model → security reasoning, investigation interpretation, report writing

Concrete model assignments will be recorded here only after `ollama list` confirms what is
installed.

## 7. Limitations

- No internet-dependent model is assumed to be free or available.
- No rate limits are documented because no external provider is configured.
- Re-verify this document whenever the OpenCode config or machine software changes.
