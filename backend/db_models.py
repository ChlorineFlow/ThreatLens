"""
db_models.py — Milestone 10

SQLAlchemy ORM model for persisted analysis results. Deliberately one
table rather than five normalized ones (samples/predictions/explanations/
risk_assessments/model_versions as separately-listed in the blueprint) --
every analysis already produces one self-contained result in practice
(detection + anomaly + family + SHAP + risk tier all computed together
for one file), so a single table avoids needless joins for the common
case of "read back this analysis" without losing any information. This
can be split further later if a real need for it shows up (e.g. tracking
multiple model VERSIONS per sample over time) -- not before.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, Integer, JSON, String

from database import Base


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    file_name = Column(String, nullable=False)
    sha256 = Column(String, nullable=False, index=True)
    file_size_bytes = Column(Integer, nullable=False)
    classification = Column(String, nullable=False)
    malicious_probability = Column(Float, nullable=False)
    anomaly_score = Column(Float, nullable=False)
    threat_level = Column(String, nullable=False, index=True)
    predicted_family = Column(String, nullable=True)
    top_contributing_features = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "analysis_id": self.id,
            "file_name": self.file_name,
            "sha256": self.sha256,
            "file_size_bytes": self.file_size_bytes,
            "classification": self.classification,
            "malicious_probability": self.malicious_probability,
            "anomaly_score": self.anomaly_score,
            "threat_level": self.threat_level,
            "predicted_family": self.predicted_family,
            "top_contributing_features": self.top_contributing_features,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }