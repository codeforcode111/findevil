# Devpost Submission Checklist

> Submission URL: https://findevil.devpost.com/
> Deadline: June 15, 2026 @ 11:45pm EDT (Beijing: June 16 11:45am)
> GitHub: https://github.com/codeforcode111/findevil

---

## Required Fields

### 1. Project Name
```
FinDevil
```

### 2. Tagline (short)
```
Evidence-Contract Autonomous IR Agent — the agent that structurally cannot lie
```

### 3. Repository URL
```
https://github.com/codeforcode111/findevil
```

### 4. Demo Video URL
```
[Upload 5min video to YouTube/Loom, paste URL here]
```
Record with: `python scripts/demo.py` + voiceover from `docs/demo-script.md`

### 5. Project Description
Copy the full content from `docs/devpost-submission.md` into the Devpost description field.

Sections to paste:
- Inspiration
- What It Does
- How We Built It
- Challenges We Ran Into
- Accomplishments That We're Proud Of
- What We Learned
- What's Next

### 6. Built With (tags)
```
python, fastmcp, pydantic, docker, claude-code, volatility3, sleuthkit, hayabusa, yara, jinja2, sqlite
```

### 7. Try It Out Link
```
https://github.com/codeforcode111/findevil#quick-start
```

---

## 8 Mandatory Submission Components

| # | Component | Where It Is | Status |
|---|-----------|-------------|--------|
| 1 | **Code Repository** | https://github.com/codeforcode111/findevil (MIT license) | Done |
| 2 | **Demo Video** (5min max) | Record `python scripts/demo.py` + voiceover | TODO |
| 3 | **Architecture Diagram** | `docs/architecture.md` (Mermaid diagrams) | Done |
| 4 | **Written Description** | `docs/devpost-submission.md` | Done |
| 5 | **Dataset Documentation** | `cases/` directory + `cases/sample/README.md` | Done |
| 6 | **Accuracy Report** | `docs/accuracy-report.md` | Done |
| 7 | **Try-It-Out Instructions** | `README.md` → Quick Start + Try It Out | Done |
| 8 | **Agent Execution Logs** | `workspace/audit_ledger.jsonl` (generated at runtime) | Done |

---

## Demo Video Recording Steps

1. Open terminal, font size 16+, dark theme
2. `cd /Users/jiaweiyu/workfiles/hackthron-june`
3. `docker compose up -d` (make sure container is running)
4. Start screen recording (QuickTime / OBS)
5. Run: `python scripts/demo.py`
6. Add voiceover using narration from `docs/demo-script.md`
7. Upload to YouTube (unlisted) or Loom
8. Paste URL into Devpost submission

---

## Key Numbers to Highlight

- **55** unit/integration tests passing
- **877** real EVTX files tested
- **37,732** detections from Hayabusa
- **27** critical + **582** high severity alerts
- **4,628** Sigma detection rules loaded
- **16** MCP tools exposed to Claude Code
- **919** evidence files hashed with SHA-256
- **0** hallucinated findings (architecturally enforced)
- **5** contract validation rules
- **3** self-correction types
- **15**-tool allowlist, **22**-command blocklist
