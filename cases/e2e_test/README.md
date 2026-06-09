# E2E Test Case: Windows Endpoint Compromise

Synthetic test case for end-to-end pipeline validation.

## Scenario

Simulated Windows endpoint compromise: Cobalt Strike beacon delivered via phishing
email (malicious Outlook attachment), persistence via registry Run key, credential
dumping via LSASS access, and an initially suspected lateral movement via RDP that
is ultimately refuted as legitimate admin activity.

## Evidence Files

All files are minimal stubs containing only magic headers and padding. They are not
real forensic artifacts and cannot be parsed by actual tools.

- `Security.evtx` -- fake EVTX with ElfFile magic header
- `SYSTEM` -- fake registry hive with regf magic header
- `memory.dmp` -- fake memory dump with embedded ASCII strings

## Ground Truth

See `ground_truth.json` for expected findings and their statuses.
