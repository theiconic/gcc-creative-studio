---
emoji: 🛡️
name: Dependabot Alert Triage (Runtime Scope Only)
description: Triage open high/critical Dependabot alerts, auto-dismissing non-exploitable ones.
on:
  schedule:
    # 07:00 Sydney (AEST, UTC+10) on weekdays. Cron is UTC and ignores DST, so
    # during daylight saving (AEDT, UTC+11) this fires at 08:00 Sydney time.
    # 21:00 UTC is the previous day, hence Sun–Thu (0-4) to cover Mon–Fri local.
    - cron: "0 21 * * 0-4"
  workflow_dispatch:
permissions:
  contents: read
  security-events: read
  vulnerability-alerts: read
  copilot-requests: write
strict: true
# Floating alias: resolves to the newest available Opus, so this picks up future
# Opus releases without an edit here.
model: opus
engine:
  id: copilot
  # Pinning a version forces a clean install to /usr/local/bin. Left unpinned,
  # gh-aw reuses a toolcache copy under /opt/hostedtoolcache and only prepends it
  # to PATH — but the agent harness spawns the absolute path /usr/local/bin/copilot
  # inside the sandbox, so it fails with ENOENT before the agent starts.
  version: 1.0.79
runs-on: ubuntu-latest
runs-on-slim: ubuntu-latest
network:
  allowed: [defaults]
tools:
  github:
    toolsets: [context, repos, dependabot]
    # Read-only installation token minted per run from the theiconic-cicd-github-access
    # App. Scopes are derived from this workflow's permissions block, so the agent
    # gets vulnerability-alerts: read and cannot dismiss anything itself.
    github-app:
      client-id: ${{ vars.CICD_APP_ID }}
      private-key: ${{ secrets.CICD_APP_PRIVATE_KEY }}
safe-outputs:
  threat-detection:
    runs-on: ubuntu-latest
    # Keep detection on the cheap tier. Without this it inherits the top-level
    # model: opus, which is wasted on a classification pass.
    engine:
      id: copilot
      model: detection
  jobs:
    dismiss-dependabot-alerts:
      description: 'Dismiss one or more Dependabot alerts. Call this tool exactly ONCE per run, passing every dismissal in the "dismissals" JSON array.'
      runs-on: ubuntu-latest
      # No vulnerability-alerts here: it is a read-only GITHUB_TOKEN scope, and
      # "write" makes Actions reject the whole workflow at parse time (instant
      # startup failure, no jobs, no log). Dismissal rights come from the App
      # token minted below instead.
      permissions:
        contents: read
      env:
        # Dry-run by default. Dismissals are only applied when the repo/org
        # Actions variable GH_AW_DEPENDABOT_ALERT_TRIAGE_APPLY is exactly "true".
        DRY_RUN: ${{ vars.GH_AW_DEPENDABOT_ALERT_TRIAGE_APPLY == 'true' && 'false' || 'true' }}
      inputs:
        dismissals:
          description: 'A JSON array (as a string) of dismissals. Each element is an object: {"alert_number": <number>, "dismissed_reason": "not_used", "dismissed_comment": "<text up to 280 chars>"}. Pass an empty array [] if there is nothing to dismiss.'
          required: true
          type: string
      steps:
        # Minted here rather than via the safe-job's github-app: key: the schema
        # accepts that key but SafeJobConfig has no field for it, so the compiler
        # silently drops it and the job would run with no token at all.
        - name: Generate GitHub App token
          id: app-token
          uses: actions/create-github-app-token@v3
          with:
            client-id: ${{ vars.CICD_APP_ID }}
            private-key: ${{ secrets.CICD_APP_PRIVATE_KEY }}
            permission-vulnerability-alerts: write
        - name: Dismiss Dependabot alerts
          env:
            GH_TOKEN: ${{ steps.app-token.outputs.token }}
          run: |
            set -euo pipefail
            DRY_RUN="${DRY_RUN:-true}"
            FILE="${GH_AW_AGENT_OUTPUT:?missing agent output file}"
            ROWS="$(mktemp)"
            SKIPPED="$(mktemp)"

            if [ "$DRY_RUN" != "false" ]; then
              echo "DRY-RUN mode (set Actions variable GH_AW_DEPENDABOT_ALERT_TRIAGE_APPLY=true to apply real dismissals)."
            fi

            # Flatten every dismissals array across all matching items. The
            # "dismissals" input is a string, so parse it with fromjson; also
            # tolerate the agent emitting a real array. Materialize to a file so
            # the loop below runs in this shell and can accumulate report rows.
            ITEMS="$(mktemp)"
            jq -c '
              .items[]?
              | select(.type == "dismiss_dependabot_alerts")
              | .dismissals
              | (if type == "string" then fromjson else . end)
              | .[]?
            ' "$FILE" > "$ITEMS"

            while read -r item; do
              [ -n "$item" ] || continue
              num=$(echo "$item" | jq -r '.alert_number // empty')
              reason=$(echo "$item" | jq -r '.dismissed_reason // empty')
              comment=$(echo "$item" | jq -r '.dismissed_comment // empty')

              if [ -z "$num" ] || [ -z "$reason" ] || [ -z "$comment" ]; then
                echo "::warning::Skipping malformed dismiss item: $item"
                printf '%s\n' "- malformed item skipped: \`$(printf '%s' "$item" | jq -Rrs '.[0:120]')\`" >> "$SKIPPED"
                continue
              fi

              # alert_number is untrusted agent output interpolated into the REST
              # path; require a strictly numeric value to avoid path/argument
              # injection or malformed requests.
              case "$num" in
                ''|*[!0-9]*) echo "::warning::Skipping alert with non-numeric alert_number '$num'"; continue ;;
              esac

              # Normalize the comment to a single line and enforce the documented
              # 280-character limit before sending it to the API. Use jq so the
              # truncation counts Unicode codepoints and never splits a
              # multi-byte UTF-8 character. Escape pipes so the comment cannot
              # break out of the markdown table cell in the run summary.
              comment=$(printf '%s' "$comment" | jq -Rrs 'gsub("[\r\n]"; " ") | .[0:280]')

              # Only not_used is permitted. Low/moderate alerts are auto-dismissed
              # by org-level GHAS rules, so this workflow never needs tolerable_risk.
              if [ "$reason" != "not_used" ]; then
                echo "::warning::Skipping alert #$num: dismissed_reason '$reason' is not allowed (only not_used)"
                printf '%s\n' "- #$num — rejected: reason \`$reason\` not allowed (only \`not_used\`)" >> "$SKIPPED"
                continue
              fi

              # Verify severity server-side rather than trusting the agent. Org-level
              # GHAS dismissal rules own low/moderate, so re-dismissing them here
              # would be redundant and would overwrite the rule's audit trail.
              severity=$(gh api "repos/${GITHUB_REPOSITORY}/dependabot/alerts/${num}" \
                --jq '.security_advisory.severity // ""' 2>/dev/null || echo "")
              package=$(gh api "repos/${GITHUB_REPOSITORY}/dependabot/alerts/${num}" \
                --jq '.dependency.package.name // "?"' 2>/dev/null || echo "?")

              case "$severity" in
                high|critical) ;;
                "")
                  echo "::warning::Could not read severity for alert #$num; skipping to stay safe"
                  printf '%s\n' "- #$num — skipped: severity could not be read from the API" >> "$SKIPPED"
                  continue
                  ;;
                *)
                  echo "::warning::Skipping alert #$num: severity '$severity' is out of scope (high/critical only)"
                  printf '%s\n' "- #$num \`$package\` — skipped: \`$severity\` is out of scope (handled by GHAS dismissal rules)" >> "$SKIPPED"
                  continue
                  ;;
              esac

              safe_comment=$(printf '%s' "$comment" | sed 's/|/\\|/g')
              alert_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/security/dependabot/${num}"

              if [ "$DRY_RUN" != "false" ]; then
                echo "[dry-run] Would dismiss alert #$num ($severity, $package): $comment"
                printf '%s\n' "| [#$num]($alert_url) | $severity | \`$package\` | would dismiss (dry-run) | $safe_comment |" >> "$ROWS"
                continue
              fi

              echo "Dismissing alert #$num ($severity, $package)"
              gh api --method PATCH \
                "repos/${GITHUB_REPOSITORY}/dependabot/alerts/${num}" \
                -f state=dismissed \
                -f dismissed_reason="$reason" \
                -f dismissed_comment="$comment"
              printf '%s\n' "| [#$num]($alert_url) | $severity | \`$package\` | dismissed | $safe_comment |" >> "$ROWS"
            done < "$ITEMS"

            # Render the dev-facing report into the workflow run summary.
            {
              echo "## Dependabot alert triage"
              echo
              if [ "$DRY_RUN" != "false" ]; then
                echo "> **Dry-run** — no alerts were actually dismissed. Set the Actions variable"
                echo "> \`GH_AW_DEPENDABOT_ALERT_TRIAGE_APPLY=true\` to apply dismissals."
                echo
              fi
              echo "Scope: **high and critical**, runtime-scoped alerts only. Low and moderate alerts"
              echo "are auto-dismissed by org-level GitHub Advanced Security rules and are not triaged here."
              echo
              if [ -s "$ROWS" ]; then
                count=$(wc -l < "$ROWS" | tr -d ' ')
                echo "### Dismissed as not exploitable ($count)"
                echo
                echo "| Alert | Severity | Package | Action | Justification |"
                echo "| --- | --- | --- | --- | --- |"
                cat "$ROWS"
                echo
              else
                echo "### No alerts dismissed"
                echo
                echo "Nothing met the bar for automatic dismissal this run."
                echo
              fi
              if [ -s "$SKIPPED" ]; then
                echo "### Rejected by guardrails ($(wc -l < "$SKIPPED" | tr -d ' '))"
                echo
                echo "These were proposed by the agent but blocked before reaching the API:"
                echo
                cat "$SKIPPED"
                echo
              fi
              echo "Anything still open needs human review — see the"
              echo "[Dependabot alerts](${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/security/dependabot?query=is%3Aopen) list."
            } >> "$GITHUB_STEP_SUMMARY"
  noop:
    report-as-issue: false
source: theiconic/gh-actions/.github/workflows/dependabot-alert-triage.md@6f6dcc100b4f8c6b211516cf95cedd185e4c124b
---

# Dependabot Alert Triage (Runtime Scope Only)

You are a security triage agent for the `${{ github.repository }}` repository. Your job is to review the currently **open** Dependabot alerts and auto-dismiss the ones that do not warrant human attention, using the exact reasons defined below. Be conservative: when in doubt, leave an alert open.

**Severity scope (high and critical only):** `low` and `moderate`/`medium` alerts are already auto-dismissed by GitHub Advanced Security dismissal rules at the org level. Do not triage or dismiss them — only consider alerts whose severity is **`high`** or **`critical`**.

## Step 1: Fetch open alerts

Use the `list_dependabot_alerts` tool with `state: open` to list the open Dependabot alerts for this repository. This tool is **paginated**: it returns at most `perPage` results per call (default 30). To avoid triaging only the first page, you must page through **every** open alert:

- Call with `perPage: 100` and `page: 1`.
- Keep incrementing `page` (2, 3, …) and calling again until a page returns fewer than `perPage` alerts (or an empty page). Accumulate the alerts from all pages before classifying.

For any alert you plan to act on, use `get_dependabot_alert` to read its full details: package name, ecosystem, severity, dependency scope, the advisory summary, the vulnerable version range, affected functions/symbols (if listed), and the manifest path.

**Severity filter (high/critical only):** Only triage alerts whose `security_advisory.severity` (or `security_vulnerability.severity`) is **`high`** or **`critical`**. Skip `low` and `medium`/`moderate` alerts entirely — org-level GitHub Advanced Security dismissal rules handle those, and re-dismissing them here would be redundant. If you cannot determine an alert's severity, leave it open for human review rather than dismissing it.

The dismissal job re-checks severity against the API and will reject anything that is not `high` or `critical`, so proposing an out-of-scope alert only produces a warning — but count it as a mistake and do not rely on that backstop.

**Scope filter (runtime only):** Also only triage alerts whose dependency scope is **runtime** (production dependencies). **Ignore development-scoped alerts entirely** — do not dismiss them and do not count them toward dismissals. An alert's scope is the `dependency.scope` field (`runtime` vs `development`); treat a missing/unknown scope as runtime to stay conservative. Leave development-scoped alerts open and untouched.

If there are no open high/critical runtime-scoped alerts, stop and call `noop` with a short note.

## Step 2: Classify each in-scope alert

For each open **high/critical, runtime-scoped** alert (skip everything excluded by Step 1), decide exactly one of the following outcomes.

### A. Not exploitable in this codebase → dismiss

Determine whether the vulnerability is actually **exploitable in this repository's code**:

- Inspect the checked-out codebase with `bash`/grep and the GitHub read tools to see how the affected package is used.
- Consider whether the vulnerable API, function, or code path identified in the advisory is actually imported and reachable in this project (production code, not just dev/test tooling where relevant).
- Consider whether the dependency is only a transitive/dev dependency with no reachable exploit path.

If you can conclude with **high confidence** that the vulnerable code path is **not reachable/used** here, dismiss it:

- `dismissed_reason`: `not_used`
- `dismissed_comment`: Write a tailored, specific justification (do not use a fixed phrase). Start with `AI triage: not exploitable in our env —` and then state the concrete reason you reached that conclusion, referencing the package and the specific evidence. Keep it under 280 characters. Examples:
  - `AI triage: not exploitable in our env — vulnerable lodash.template() is never imported; only lodash.get/pick are used in src/.`
  - `AI triage: not exploitable in our env — webpack is a build-only devDependency and never runs in production/runtime code.`
  - `AI triage: not exploitable in our env — the affected axios follow-redirects path is unused; all calls set maxRedirects: 0.`

### B. Exploitable or uncertain → leave open

If the vulnerability appears exploitable, or you cannot determine reachability with high confidence, **do not dismiss it**. Leave it open for human review.

## Step 3: Act

- Collect **all** alerts you decided to dismiss (category A) into a single JSON array. Each element is an object:
  `{"alert_number": <number>, "dismissed_reason": "<reason>", "dismissed_comment": "<text>"}`.
- Call the `dismiss_dependabot_alerts` safe output **exactly once**, passing that whole array as the `dismissals` input. Do **not** call it once per alert — batch every dismissal into the single call. If nothing should be dismissed, pass an empty array `[]` (or just skip the tool and call `noop`).
- Every dismissal uses `dismissed_reason` `not_used` and a **tailored** `dismissed_comment` that explains the specific reason the vulnerability is not exploitable here, as described above.
- After the dismissal call, always call `noop` with a one-line summary of the counts.

## Step 4: Write the report

Your final response is appended to the workflow run summary, where developers read it. End the run by emitting a markdown report in exactly this shape — no preamble, no closing commentary:

```markdown
## Triage summary

- Reviewed: N high/critical runtime alerts
- Dismissed as not exploitable: N
- **Left open for review: N**
- Skipped as out of scope: N (low/moderate severity or development-scoped)

### Needs human review

| Alert | Severity | Package | Why it needs a human |
| --- | --- | --- | --- |
| [#31](https://github.com/OWNER/REPO/security/dependabot/31) | critical | `next` | Vulnerable SSR image path is reachable from `pages/product/[id].tsx`; needs an upgrade to 14.2.21. |
```

Rules for the report:

- Use the real repository (`${{ github.repository }}`) in alert links so they are clickable.
- The **Needs human review** table is the most valuable part — it is the developers' actionable to-do list. One row per alert left open, with a concrete reason and, where you can determine it, the fix version or the file/symbol that makes it reachable.
- If nothing was left open, replace the table with a single line: `No high/critical alerts need human review.`
- Do not repeat the dismissal table; the safe job already renders dismissals into the run summary.
- Keep each "Why it needs a human" cell to one or two sentences and escape any `|` characters.

Example `dismissals` payload:

```json
[
  {"alert_number": 27, "dismissed_reason": "not_used", "dismissed_comment": "AI triage: not exploitable in our env — vulnerable lodash.template() is never imported; only lodash.get/pick are used in src/."}
]
```

## Guardrails

- Only triage `high` and `critical` alerts; never dismiss a `low` or `medium`/`moderate` alert — org-level GHAS dismissal rules own those.
- Only triage runtime-scoped alerts; never dismiss a development-scoped alert.
- Never dismiss an alert whose exploitability you are unsure about.
- `not_used` is the only reason this workflow should use; never use `tolerable_risk`.
- The comment must reflect the actual, alert-specific reasoning — never a generic placeholder.
- Call `dismiss_dependabot_alerts` at most once per run.
- Never modify repository files or open issues/PRs — dismissal is the only write action.
