"""Tests for Parallel Agent Orchestrator pipeline."""
from pathlib import Path

from phi_scanner.agent_orchestrator import ParallelAgentOrchestrator
from phi_scanner.engine import ScanEngine
from phi_scanner.recognizers.aadhaar import verhoeff_check_digit
from phi_scanner.recognizers.gstin import _gstin_check_digit


def make_aadhaar(prefix: str) -> str:
    return prefix + verhoeff_check_digit(prefix)


def make_gstin(prefix14: str) -> str:
    return prefix14 + _gstin_check_digit(prefix14)


def test_agent_orchestrator_csv_scan(tmp_path: Path) -> None:
    csv_file = tmp_path / "agents_test.csv"

    valid_aadhaar = make_aadhaar("23456789012")
    valid_gstin = make_gstin("29ABCPD1234E1Z")

    content = f"name,aadhaar_no,pan_no,gstin_no,mobile\n"
    content += f"Priya Sharma,{valid_aadhaar},ABCPD1234E,{valid_gstin},9876543210\n"

    csv_file.write_text(content, encoding="utf-8")

    orchestrator = ParallelAgentOrchestrator(num_workers=2)
    findings = list(orchestrator.orchestrate_path(csv_file))

    entity_types = {f.entity_type for f in findings}
    assert "AADHAAR" in entity_types
    assert "PAN" in entity_types
    assert "GSTIN" in entity_types
    assert "IN_MOBILE" in entity_types

    # Verify agent IDs
    agent_ids = {f.agent_id for f in findings}
    assert "agent-aadhaar" in agent_ids
    assert "agent-pan" in agent_ids


def test_scan_engine_scan_path_agents(tmp_path: Path) -> None:
    csv_file = tmp_path / "engine_agents_test.csv"
    valid_aadhaar = make_aadhaar("34567890123")
    csv_file.write_text(f"aadhaar_no\n{valid_aadhaar}\n", encoding="utf-8")

    engine = ScanEngine()
    findings = list(engine.scan_path_agents(csv_file, num_agents=2))

    assert len(findings) >= 1
    assert findings[0].entity_type == "AADHAAR"
    assert findings[0].confidence == "HIGH"
