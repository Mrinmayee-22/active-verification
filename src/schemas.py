"""Data contract for the Active Verification pipeline.

Every stage (Detect -> Investigate -> Unmask -> Explain) reads and writes
these models. A PipelineRecord starts with only an Artifact and gains one
stage result at a time as it moves through the pipeline.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------- Enums: fixed vocabularies, so typos fail loudly ----------

class ArtifactType(str, Enum):
    EMAIL = "email"
    WEBSITE = "website"


class Label(str, Enum):
    """Detect stage output label."""
    PHISHING = "phishing"
    LEGITIMATE = "legitimate"


class EvidenceSource(str, Enum):
    """Which OSINT tool produced a piece of evidence."""
    WHOIS = "whois"
    DNS = "dns"
    SPF = "spf"
    DKIM = "dkim"
    VIRUSTOTAL = "virustotal"
    URLHAUS = "urlhaus"


class Direction(str, Enum):
    """Which way a single piece of evidence points."""
    MALICIOUS = "malicious"
    BENIGN = "benign"
    NEUTRAL = "neutral"


class Verdict(str, Enum):
    """Judge agent's final decision in the Investigate stage."""
    MALICIOUS = "malicious"
    BENIGN = "benign"
    INCONCLUSIVE = "inconclusive"


# ---------- Models ----------

class Artifact(BaseModel):
    """The thing being checked: one email or one website."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))  # unique per artifact
    artifact_type: ArtifactType                                  # email or website
    content: str                                                 # raw email text or page HTML
    sender: Optional[str] = None                                 # emails only
    url: Optional[str] = None                                    # websites only


class DetectResult(BaseModel):
    """Output of the Detect stage."""
    label: Label                                  # classifier's decision
    confidence: float = Field(ge=0.0, le=1.0)     # probability of that label, 0 to 1
    model_name: str                               # e.g. "tfidf-logreg", "deberta-v3"


class Evidence(BaseModel):
    """One OSINT finding gathered during Investigate."""
    source: EvidenceSource                        # which tool found it
    finding: str                                  # plain-language finding
    direction: Direction                          # malicious / benign / neutral
    raw_response: Optional[str] = None            # raw tool output, kept for audit


class InvestigateResult(BaseModel):
    """Output of the Investigate stage (prosecution / defense / judge)."""
    evidence: list[Evidence] = Field(default_factory=list)  # all findings gathered
    prosecution_argument: str                     # case that it is malicious
    defense_argument: str                         # case that it is legitimate
    verdict: Verdict                              # judge's decision
    judge_reasoning: str                          # why the judge decided that


class PipelineRecord(BaseModel):
    """One artifact plus whatever each stage has produced so far."""
    artifact: Artifact
    detect: Optional[DetectResult] = None                # filled by Detect
    investigate: Optional[InvestigateResult] = None      # filled by Investigate
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )