import pytest
from pydantic import ValidationError

from src.schemas import (
    Artifact,
    ArtifactType,
    DetectResult,
    Direction,
    Evidence,
    EvidenceSource,
    InvestigateResult,
    Label,
    PipelineRecord,
    Verdict,
)


def make_full_record() -> PipelineRecord:
    """Build a record that has passed through Detect and Investigate."""
    artifact = Artifact(
        artifact_type=ArtifactType.EMAIL,
        content="Your account is locked. Click here to verify.",
        sender="support@paypa1-security.com",
    )
    detect = DetectResult(label=Label.PHISHING, confidence=0.93, model_name="tfidf-logreg")
    investigate = InvestigateResult(
        evidence=[
            Evidence(
                source=EvidenceSource.WHOIS,
                finding="Domain registered 3 days ago",
                direction=Direction.MALICIOUS,
                raw_response="Creation Date: 2026-10-04",
            )
        ],
        prosecution_argument="Newly registered lookalike domain urging urgent action.",
        defense_argument="No direct evidence of malware or credential theft yet.",
        verdict=Verdict.MALICIOUS,
        judge_reasoning="Domain age and lookalike spelling outweigh the weak defense.",
    )
    return PipelineRecord(artifact=artifact, detect=detect, investigate=investigate)


def test_confidence_above_one_rejected():
    with pytest.raises(ValidationError):
        DetectResult(label=Label.PHISHING, confidence=1.7, model_name="x")


def test_confidence_below_zero_rejected():
    with pytest.raises(ValidationError):
        DetectResult(label=Label.PHISHING, confidence=-0.1, model_name="x")


def test_confidence_boundaries_accepted():
    DetectResult(label=Label.LEGITIMATE, confidence=0.0, model_name="x")
    DetectResult(label=Label.PHISHING, confidence=1.0, model_name="x")


def test_invalid_label_rejected():
    with pytest.raises(ValidationError):
        DetectResult(label="phising", confidence=0.5, model_name="x")  # typo on purpose


def test_new_record_has_no_stage_results():
    artifact = Artifact(artifact_type=ArtifactType.WEBSITE, content="<html></html>", url="http://x.test")
    record = PipelineRecord(artifact=artifact)
    assert record.detect is None
    assert record.investigate is None
    assert record.artifact.sender is None


def test_each_artifact_gets_unique_id():
    a = Artifact(artifact_type=ArtifactType.EMAIL, content="a")
    b = Artifact(artifact_type=ArtifactType.EMAIL, content="a")
    assert a.id != b.id


def test_json_roundtrip():
    record = make_full_record()
    restored = PipelineRecord.model_validate_json(record.model_dump_json())
    assert restored == record


def test_print_example_json():
    print(make_full_record().model_dump_json(indent=2))