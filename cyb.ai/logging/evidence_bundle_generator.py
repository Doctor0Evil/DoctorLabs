import hashlib
import json
from datetime import datetime

class EvidenceBundle:
    def __init__(self, event_id: str):
        self.event_id = event_id
        self.timestamp = datetime.utcnow().isoformat()
        self.threat_family = None
        self.neurorights_at_stake = []
        self.risk_score = 0.0
        self.signatures = []

    def add_evidence(self, threat_family: str, neurorights: list, risk_score: float):
        self.threat_family = threat_family
        self.neurorights_at_stake = neurorights
        self.risk_score = risk_score

    def sign(self, private_key: str):
        bundle_str = f"{self.event_id}{self.timestamp}{self.threat_family}{self.risk_score}"
        self.signatures.append(hashlib.sha256(bundle_str.encode()).hexdigest())

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump({
                "event_id": self.event_id,
                "timestamp": self.timestamp,
                "threat_family": self.threat_family,
                "neurorights_at_stake": self.neurorights_at_stake,
                "risk_score": self.risk_score,
                "signatures": self.signatures
            }, f, indent=2)

# Example usage:
bundle = EvidenceBundle("account_action_12345")
bundle.add_evidence(
    threat_family="LEO_Safety_Request",
    neurorights=["mental_privacy", "cognitive_liberty"],
    risk_score=0.85
)
bundle.sign("your_private_key_here")
bundle.save("/var/log/cyb_ai/evidence_bundles/account_action_12345.json")
