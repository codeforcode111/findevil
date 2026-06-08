from __future__ import annotations

CORROBORATION_POLICIES: dict[str, dict] = {
    "persistence": {
        "description": "Persistence claims require >=2 artifact types",
        "min_sources": 2,
        "mitre_tactics": ["TA0003"],
        "mitre_techniques_prefix": ["T1547", "T1053", "T1543", "T1546"],
    },
    "lateral_movement": {
        "description": "Lateral movement requires network + auth evidence",
        "min_sources": 2,
        "mitre_tactics": ["TA0008"],
        "mitre_techniques_prefix": ["T1021", "T1570"],
    },
    "exfiltration": {
        "description": "Exfiltration requires staging + transfer evidence",
        "min_sources": 2,
        "mitre_tactics": ["TA0010"],
        "mitre_techniques_prefix": ["T1041", "T1048", "T1567"],
    },
}


def get_min_sources_for_technique(technique: str) -> int:
    for policy in CORROBORATION_POLICIES.values():
        for prefix in policy["mitre_techniques_prefix"]:
            if technique.startswith(prefix):
                return policy["min_sources"]
    return 1
