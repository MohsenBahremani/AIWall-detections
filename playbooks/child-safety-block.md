# Playbook: Child safety / content policy block

**Trigger:** AIWall blocked a request because content-category policy matched (typically a **child** profile under the family preset).

| Signal | Value |
|---|---|
| Audit `decision` | `block` |
| Audit `reason` | `category-blocked` |
| Audit `categories` | e.g. `sexual`, plus policy-defined sets (`explicit`, `unsafe`, `violence`) |
| Audit `policy_id` | e.g. `child-block-explicit`, `block-child-categories` |
| Wazuh | Rule **100211** |
| Sigma / Loki | `aiwall_policy_block` |
| ATLAS | [AML.T0048](https://atlas.mitre.org/) External Harms |
| Sample | `req-policy-001` |

Upstream behavior: [AIWall family-mode.md](https://github.com/MohsenBah/AIWall/blob/main/docs/family-mode.md).

## Triage (5–15 min)

1. Pull the audit row (`request_id`, `user_id`, `categories`, `policy_id`, `timestamp`). Raw prompts are **not** in `aiwall.audit.v1` — use parent review / blocked UI if you need conversation context.
2. Confirm the profile **role** is `child` (or whatever role the policy targets). Adult profiles should not match `user.role == "child"` rules unless you added custom policy.
3. Decide what happened:
   - Curious / accidental ask from the child
   - Jailbreak-style attempt to bypass filters
   - Wrong profile key used on a shared device (adult browsing as child, or vice versa)
   - Classifier over-match (keyword category false positive)
4. Check **frequency** for that `user_id` in the last 24h (Blocked page filter, weekly family report, or Loki `aiwall_policy_block`).
5. Note device / Open WebUI account mapping if you run the family stack.

## Response

| Priority | Action |
|---|---|
| P1 | If the block suggests **active bypass attempts** (repeated, escalating), pause the child profile key (`aiwall profiles` / rotate key) until a parent reviews. |
| P1 | Talk with the child / household as appropriate — this is a family-safety control, not only a SOC ticket. |
| P2 | Verify Open WebUI **Direct Connection** still uses the child AIWall API key (not an adult or gateway bootstrap key). |
| P2 | Review related rows: secrets (`secret-detected`) and daily-limit hits for the same profile. |
| P3 | If clearly a **false category** match, refine keywords/policies carefully; prefer tighter `when:` conditions over disabling the child preset. |

## Containment checklist

- [ ] Profile identity confirmed (right child, right key)
- [ ] Parent/guardian aware of the event and time window
- [ ] No unexpected adult traffic attributed to the child `user_id`
- [ ] Key rotated if the device was shared or the key was exposed
- [ ] Follow-up: glance at `/reports/weekly` for pattern, not one-off noise

## False positives

- Benign homework / health / news prompts that hit coarse keyword categories
- Non-child traffic mistakenly using a child API key
- Custom policies that reuse `category-blocked` for non-family use cases (triage with `policy_id`)

## Related

- Coverage: [docs/coverage-matrix.md](../docs/coverage-matrix.md)
- Daily limit companion alert: Wazuh **100213** / Loki `aiwall_daily_limit`
- Sibling playbooks: [secret-leak-detected.md](secret-leak-detected.md), [suspicious-agent-action.md](suspicious-agent-action.md)
