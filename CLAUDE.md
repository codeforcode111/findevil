# FinDevil: Evidence-Contract Autonomous IR Agent

## What This Is

An autonomous incident response agent. You (Claude Code) are the reasoning engine. The MCP server provides forensic tools, evidence contracts, and audit trails.

## Investigation Workflow

1. **Initialize**: Call `investigate_case` with the evidence directory path
2. **Triage**: Call `list_evidence` to see what's available
3. **Analyze**: Use forensic tools based on evidence types:
   - Memory dumps → `analyze_memory` (Volatility 3)
   - Disk images → `analyze_filesystem` (Sleuth Kit)
   - EVTX logs → `scan_eventlogs` (Hayabusa)
   - Registry hives → `analyze_registry` (RegRipper)
   - File scanning → `scan_yara` (YARA)
   - Timelines → `build_timeline` (Plaso)
   - Artifacts → `analyze_artifacts` (MFT, Prefetch, Amcache)
4. **Submit findings**: Call `submit_finding` — the contract compiler enforces evidence rules
5. **Self-correct**: If tools fail, try alternatives. If evidence contradicts, call `add_contradiction_to_finding`
6. **Report**: Call `generate_report` for the final output

## Rules

- Every finding MUST cite tool_run_ids from actual tool executions
- CONFIRMED status requires >=2 independent evidence sources
- If you find contradicting evidence, report it honestly via `add_contradiction_to_finding`
- When a tool fails, try an alternative before giving up
- Report what you checked but did NOT find (negative findings matter)
- Never claim certainty beyond what the evidence supports
