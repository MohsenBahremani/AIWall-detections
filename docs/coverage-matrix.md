# MITRE ATLAS coverage matrix

Maps every AIWall-detections **detection** to at least one [MITRE ATLAS](https://atlas.mitre.org/) technique.

Machine-readable source: [`atlas-mapping.json`](atlas-mapping.json) (validated by `validation/validate_rules.py`).

OWASP LLM Top 10 column is informational (developer risk lens). ATT&CK IDs are only listed where a traditional cyber technique is a close cousin (e.g. unsecured credentials).

## Coverage matrix

| Detection | Wazuh | Sigma | Loki | Primary ATLAS | Secondary ATLAS | OWASP LLM |
|---|---|---|---|---|---|---|
| Secret leak blocked | 100210 | `aiwall_secret_leak_blocked` | `aiwall_secret_leak_blocked` | [AML.T0057](https://atlas.mitre.org/) LLM Data Leakage | AML.T0055 Unsecured Credentials | LLM02 |
| Content policy block | 100211 | `aiwall_policy_block` | `aiwall_policy_block` | [AML.T0048](https://atlas.mitre.org/) External Harms | — | LLM05 |
| Cost threshold block | 100212 | `aiwall_cost_threshold` | `aiwall_cost_threshold` | [AML.T0034](https://atlas.mitre.org/) Cost Harvesting | — | LLM10 |
| Daily usage limit | 100213 | `aiwall_daily_limit` | `aiwall_daily_limit` | [AML.T0034](https://atlas.mitre.org/) Cost Harvesting | AML.T0046 Spamming ML System with Chaff Data | LLM10 |
| Agent approval denied | — | — | `aiwall_agent_approval_denied` | [AML.T0050](https://atlas.mitre.org/) Command and Scripting Interpreter | AML.T0053 LLM Plugin Compromise | LLM06 |
| Secret redacted | — | — | `aiwall_secret_redacted` | [AML.T0057](https://atlas.mitre.org/) LLM Data Leakage | — | LLM02 |
| Upstream provider errors | — | — | `aiwall_upstream_error` | [AML.T0029](https://atlas.mitre.org/) Denial of ML Service | — | LLM10 |

Roll-up query `aiwall_all_blocks` is not a separate detection; it surfaces the block rows above.

## Technique notes

| ATLAS ID | Why it appears here |
|---|---|
| **AML.T0057** | Secrets (or other sensitive tokens) leaving via an LLM request — blocked or redacted by AIWall |
| **AML.T0055** | Secrets in prompts are a form of unsecured credential exposure into a third-party model path |
| **AML.T0048** | Category / family-mode blocks stop content that can cause external harm |
| **AML.T0034** | Cost-threshold and daily-limit blocks stop abusive or runaway spend |
| **AML.T0046** | Daily limits also blunt chaff / flood style usage |
| **AML.T0050** | Agent shell / interpreter actions denied after approval failure |
| **AML.T0053** | Agent tools/plugins are the execution surface being constrained |
| **AML.T0029** | Upstream `decision=error` is an availability signal (dependency or resource failure), not proof of attack |

## Gaps (honest)

These ATLAS techniques are **not** covered by current Community detections (candidates for later packs / Phase 7 red-team):

| ATLAS ID | Name | Gap |
|---|---|---|
| AML.T0051 | Prompt Injection | No dedicated injection-signature rule yet (agent warn paths are adjacent only) |
| AML.T0054 | LLM Jailbreak | No jailbreak classifier detection |
| AML.T0024 | Exfiltration via ML Inference API | Partial overlap with secret leak; no model-extraction / high-volume query rule |
| AML.T0056 | LLM Meta Prompt Extraction | Not detected |

## Maintaining the matrix

1. Add or change a detection → update `atlas-mapping.json` (every entry needs `atlas` with ≥1 id).
2. Run `python3 validation/validate_rules.py`.
3. Refresh this markdown table if the JSON changed (keep them in sync; CI checks JSON completeness, not the markdown wording).
