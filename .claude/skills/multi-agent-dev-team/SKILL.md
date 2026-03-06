---
name: multi-agent-dev-team
description: >
  Orchestrate a full software development team using multiple Claude agents with specialized roles
  (PM, devs, code reviewer, UX designer, QA, security reviewer, tech writer, architect).
  Use this skill whenever the user wants to build features using a multi-agent team,
  wants code reviewed by multiple perspectives, asks for "team review", "multi-agent",
  "dev team simulation", "have agents build this", or wants any kind of collaborative
  AI development workflow. Also trigger when the user says "use the dev team",
  "spin up the team", "full team review", or references agent roles like PM, reviewer, QA.
disable-model-invocation: true
---

# Multi-Agent Development Team

This skill orchestrates a virtual software development team where each Claude agent
plays a specialized role. The agents collaborate through structured handoffs, producing
higher-quality output than any single agent.

## How It Works

The orchestrator (you) manages the workflow by:
1. Reading the user's request
2. Having the PM agent break it down into specs
3. Dispatching to dev agents for implementation
4. Running review cycles (code review, security, QA)
5. Iterating based on feedback
6. Delivering the final output

## Agent Roles

Read the role prompts from `references/roles/` before dispatching to any agent.
Each role file contains the complete system prompt for that agent.

Available roles:
| Role | File | When to Use |
|------|------|-------------|
| Product Manager | `pm.md` | **Always first.** Breaks down requirements into specs |
| Architect | `architect.md` | For system design decisions, tech stack, patterns |
| Dev Lead | `dev-lead.md` | Primary implementer, owns the main code |
| Dev 2 (Peer) | `dev-peer.md` | Second implementer OR peer reviewer of Dev Lead's code |
| Code Reviewer (PR Reviewer) | `code-reviewer.md` | **Always last before merge.** Senior staff-level review after implementation |
| UX Designer | `ux-designer.md` | Reviews UI/UX decisions, suggests improvements |
| QA Engineer | `qa-engineer.md` | Writes tests, finds edge cases, validates behavior |
| Security Reviewer | `security-reviewer.md` | Checks for vulnerabilities, auth issues, data leaks |
| Tech Writer | `tech-writer.md` | Generates documentation from implemented code |

## KeyClaw Project Context

This is a **Rust** project — a MITM proxy for redacting secrets from AI CLI traffic.

- **Stack**: Rust, hudsucker (proxy engine), regex, toml, AES-GCM encryption
- **Architecture**: Single binary, modular source files, no microservices
- **Testing**: `cargo test` — integration tests, e2e CLI tests, unit tests
- **Build**: `cargo build --release`
- **Detection**: 220+ gitleaks.toml rules compiled natively into Rust regex

### KeyClaw-Specific Review Priorities
- **Security is paramount** — this is a security tool. Any code handling secrets, vault, or crypto must get security review.
- **Performance matters** — regex compilation and per-request secret scanning must be fast.
- **No external deps at runtime** — gitleaks rules are bundled, no subprocess calls.
- **Placeholder integrity** — placeholder format `{{KEYCLAW_SECRET_<prefix>_<hash>}}` must be preserved across all code paths.

## Workflow Modes

### Mode 1: Full Team Build (default for new features)
```
User Request
    → PM (spec)
    → Architect (design)
    → Dev Lead (implement) + Dev Peer (implement alternate/supporting)
    → Dev Lead ↔ Dev Peer (cross-review)
    → Code Reviewer / PR Reviewer (final review)
    → Security Reviewer (mandatory for this project)
    → QA Engineer (tests)
    → Dev Lead (fixes from all reviews)
    → Tech Writer (docs)
    → Deliver to user
```

### Mode 2: Review Only (for existing code)
```
User provides code
    → Code Reviewer / PR Reviewer
    → Security Reviewer
    → QA Engineer
    → Consolidated feedback to user
```

### Mode 3: Quick Build (small tasks)
```
User Request
    → PM (lightweight spec)
    → Dev Lead (implement)
    → Code Reviewer / PR Reviewer (review)
    → Deliver to user
```

## Ralph Loop Integration

When running inside a Ralph Loop (`/ralph-loop`), the dev team workflow adapts:

### How It Works with Ralph Loop
1. **First iteration**: PM specs the task, Dev Lead implements
2. **Second iteration**: PR Reviewer reviews, flags issues
3. **Subsequent iterations**: Dev Lead fixes issues from review, PR Reviewer re-reviews
4. **Completion**: When PR Reviewer approves, output `<promise>APPROVED</promise>`

### Ralph Loop PROMPT.md Template
```markdown
You are running a multi-agent dev team loop on the KeyClaw project.

## Task
[DESCRIBE THE TASK HERE]

## Workflow
1. Check git status and recent commits to see what's been done
2. If no PM spec exists in .claude/dev-team-state.md, act as PM and create one
3. If spec exists but not implemented, act as Dev Lead and implement
4. If implemented but not reviewed, act as PR Reviewer and review
5. If review has issues, act as Dev Lead and fix them
6. If review passes, run `cargo test && cargo build --release`
7. If all green, commit and output <promise>APPROVED</promise>

## State File
Track progress in `.claude/dev-team-state.md`:
- Current phase: pm-spec | architect | dev | review | fix | qa | done
- PM Spec: [inline or reference]
- Review findings: [list]
- Iteration count: N

## Rules
- Always read CLAUDE.md first for project context
- Always run `cargo test` before claiming anything works
- PR Reviewer MUST check: correctness, security, performance, Rust idioms
- Never skip the review phase
```

## Orchestration Instructions

When dispatching to an agent, use this pattern with Claude Code subagents:

```bash
claude -p "$(cat .claude/skills/multi-agent-dev-team/references/roles/<role>.md)

---

CONTEXT FROM PREVIOUS AGENTS:
<paste relevant context>

---

YOUR TASK:
<specific task for this agent>"
```

### Handoff Format

Each agent MUST end their output with a structured handoff block:

```
## HANDOFF
- **Status**: complete | needs-revision | blocked
- **Key Decisions**: [list of decisions made]
- **Open Questions**: [list of unresolved items]
- **For Next Agent**: [specific instructions or context needed]
```

### Conflict Resolution

When agents disagree (e.g., Dev Lead vs Code Reviewer):
1. Present both perspectives to the user
2. If user doesn't want to arbitrate, the Code Reviewer's opinion wins for code quality,
   the PM's opinion wins for scope, and the Architect's opinion wins for design patterns

### Iteration Limits

- Max 3 review cycles per agent pair
- If still unresolved after 3 cycles, escalate to user
- For large features, break into sub-tasks and run the pipeline per sub-task

## What to Tell the User

After running the full pipeline, present:
1. The final implemented code
2. A summary of key decisions made by the team
3. Any open concerns from reviewers
4. Test coverage summary from QA
5. Documentation from Tech Writer
