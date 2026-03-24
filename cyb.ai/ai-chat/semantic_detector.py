from typing import Dict, List
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest

class SemanticDetector:
    def __init__(self):
        self.vectorizer = TfidfVectorizer()
        self.model = IsolationForest(contamination=0.01)
        self.rogue_score_threshold = 0.7

    def detect_anomalies(self, interactions: List[str]) -> Dict[str, float]:
        tfidf_matrix = self.vectorizer.fit_transform(interactions)
        scores = self.model.fit_predict(tfidf_matrix)
        rogue_scores = [-s for s in scores]  # Convert to positive risk score
        return {"rogue_scores": rogue_scores, "mean_rogue_score": np.mean(rogue_scores)}

# Example usage:
detector = SemanticDetector()
interactions = ["Debug my session", "Crosslink my EEG data", "I need to reset my account"]
result = detector.detect_anomalies(interactions)
if result["mean_rogue_score"] > detector.rogue_score_threshold:
    print(f"Rogue score {result['mean_rogue_score']} exceeded threshold. Escalate to governance.")
