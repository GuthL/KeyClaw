#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

OUTPUT_PATH = Path("docs/plans/2026-03-07-production-readiness-project.md")
PLAN_PATH = "docs/plans/2026-03-07-production-readiness.md"
PROJECT_URL = "https://github.com/users/GuthL/projects/1"
REPO_URL = "https://github.com/GuthL/KeyClaw"
PRODUCTION_READINESS_LABEL = "production-readiness"

ISSUE_ONE_APPENDIX = """Decision summary:

- Supported release binaries are fixed to `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`.
- v0.x vault protection defaults to a generated machine-local `vault.key`; `KEYCLAW_VAULT_PASSPHRASE` remains an explicit override only.
- README-first documentation plus `SECURITY.md`, `CONTRIBUTING.md`, and the maintainer release checklist is the complete v0.x docs surface; no separate docs site is required before launch.
- The current scrubbed leveled logging contract is sufficient for v0.x; a full structured logging migration is not a launch blocker.
- `KEYCLAW_NOTICE_MODE` now ships `verbose`, `minimal`, and `off`; v0.x keeps the current provider-specific injection points while letting operators pick the notice verbosity.
"""

ISSUE_ONE_CHECKED_CRITERIA = {
    "- [ ] The supported platform matrix is explicitly documented.": "- [x] The supported platform matrix is explicitly documented.",
    "- [ ] The vault/key-management approach for v0.x is explicitly decided and recorded.": "- [x] The vault/key-management approach for v0.x is explicitly decided and recorded.",
    "- [ ] The documentation format decision is recorded.": "- [x] The documentation format decision is recorded.",
    "- [ ] The logging-scope decision is recorded.": "- [x] The logging-scope decision is recorded.",
    "- [ ] The notice-mode decision is recorded.": "- [x] The notice-mode decision is recorded.",
    "- [ ] `docs/plans/2026-03-07-production-readiness.md` and the project backlog reflect the final decisions with no remaining release-blocking ambiguity.": "- [x] The plan and project backlog reflect the final decisions with no remaining release-blocking ambiguity.",
}


def run_gh_json(args: list[str]) -> list[dict[str, object]]:
    result = subprocess.run(
        ["gh", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def label_names(issue: dict[str, object]) -> list[str]:
    labels = issue.get("labels", [])
    if not isinstance(labels, list):
        return []
    return [label["name"] for label in labels if isinstance(label, dict) and "name" in label]


def milestone_title(issue: dict[str, object]) -> str:
    milestone = issue.get("milestone")
    if isinstance(milestone, dict):
        title = milestone.get("title")
        if isinstance(title, str) and title.strip():
            return title.strip()
    return "(none)"


def normalize_task_title(title: str) -> str:
    prefix = "[Production Readiness] "
    return title[len(prefix) :] if title.startswith(prefix) else title


def render_issue_body(issue: dict[str, object]) -> str:
    body = str(issue.get("body", "")).strip()
    if int(issue["number"]) == 1:
        for old, new in ISSUE_ONE_CHECKED_CRITERIA.items():
            body = body.replace(old, new)
        body = f"{body}\n\n{ISSUE_ONE_APPENDIX}".strip()
    return body


def render_issue_section(issue: dict[str, object]) -> str:
    number = int(issue["number"])
    title = str(issue["title"]).strip()
    url = str(issue["url"]).strip()
    milestone = milestone_title(issue)
    labels = ", ".join(f"`{name}`" for name in label_names(issue))
    body = render_issue_body(issue)

    section = [
        f"### Issue #{number}",
        "",
        f"Title: {title}  ",
        f"Link: {url}  ",
        f"Milestone: {milestone}  ",
        f"Labels: {labels}",
        "",
        "GitHub is the source of truth for live issue state, assignees, project fields, priority, and target dates for this issue.",
        "",
        body,
        "",
    ]
    return "\n".join(section)


def render_markdown(issues: list[dict[str, object]]) -> str:
    lines = [
        "# KeyClaw Production Readiness Project",
        "",
        f"Source plan: `{PLAN_PATH}`  ",
        f"GitHub Project: {PROJECT_URL}  ",
        f"Repository: {REPO_URL}",
        "",
        f"This file is the local acceptance-criteria mirror for KeyClaw production-readiness work. GitHub is the source of truth for live issue state, assignees, project status, priority, and target dates.",
        "",
        "Run `scripts/sync-production-readiness-project.py` to refresh this mirror from GitHub.",
        "",
        "This mirror intentionally preserves only the issue list, milestone association, labels, and acceptance/detail text that we want available in-repo during release work.",
        "",
        "## Milestone Map",
        "",
        "| Milestone | Focus |",
        "| --- | --- |",
        "| M0 | Lock release scope and open decisions. Due March 10, 2026 |",
        "| M1 | Security closure. Due March 14, 2026 |",
        "| M2 | Reliability and operator UX closure. Due March 21, 2026 |",
        "| M3 | Release engineering and documentation closure. Due March 28, 2026 |",
        "| M4 | Release candidate verification and sign-off. Due April 4, 2026 |",
        "",
        "## Backlog",
        "",
        "| Issue | Milestone | Labels | Task |",
        "| --- | --- | --- | --- |",
    ]

    for issue in issues:
        number = int(issue["number"])
        url = str(issue["url"]).strip()
        labels = ", ".join(f"`{name}`" for name in label_names(issue))
        title = normalize_task_title(str(issue["title"]).strip())
        milestone = milestone_title(issue)
        lines.append(f"| [#{number}]({url}) | {milestone} | {labels} | {title} |")

    lines.extend(["", "## Task Details", ""])

    for issue in issues:
        lines.append(render_issue_section(issue))

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    issues = run_gh_json(
        [
            "issue",
            "list",
            "--state",
            "all",
            "--label",
            PRODUCTION_READINESS_LABEL,
            "--limit",
            "100",
            "--json",
            "number,title,url,labels,milestone,body",
        ]
    )
    issues.sort(key=lambda issue: int(issue["number"]))
    OUTPUT_PATH.write_text(render_markdown(issues), encoding="utf-8")
    print(f"updated {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
