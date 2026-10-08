from ibn.intent.validation import validate_intents
from ibn.kb.state import IntentRecord
from ibn.models.intent import Intent
from ibn.models.report import Severity
from tests.conftest import intent


def test_kb_is_consistent(kb):
    assert kb.check() == []


def test_kb_detects_p2p_convention_violation(kb):
    kb.interfaces["R2"]["Ethernet0/0"].ip = __import__("ipaddress").IPv4Interface("10.1.2.9/24")
    assert any("expected host part .2" in i.message for i in kb.check())


def test_endpoints_resolve(kb):
    assert str(kb.endpoint_net("vpc4")) == "10.0.1.10/32"
    assert str(kb.endpoint_net("Finance")) == "10.0.3.0/24"
    assert str(kb.endpoint_net("R2")) == "10.1.2.2/32"
    assert str(kb.endpoint_net("10.9.0.0/16")) == "10.9.0.0/16"


def test_schema_errors(kb):
    bad = intent(expectations=[{"src": "HR", "dst": "Finance", "protocol": "icmp", "port": 80, "expect": "deny"}])
    _, report = validate_intents([bad], kb, [])
    assert not report.passed and "only valid for tcp/udp" in report.errors()[0].message
    _, report = validate_intents([{"category": "x"}], kb, [])
    assert "description" in report.errors()[0].message


def test_unknown_entities_and_guardrail(kb):
    raw = intent(scope={"groups": ["Sales"]},
                 expectations=[{"src": "Marketing", "dst": "HR", "expect": "deny"},
                               {"src": "10.1.2.0/24", "dst": "10.2.3.0/24", "expect": "deny"}])
    _, report = validate_intents([raw], kb, [])
    msgs = " ".join(e.message for e in report.errors())
    assert "unknown group 'Sales'" in msgs and "unknown endpoint 'Marketing'" in msgs and "guardrail" in msgs


def test_intent_without_expectations_is_a_warning(kb):
    _, report = validate_intents([intent(description="Log all denied packets", expectations=[])], kb, [])
    assert report.passed
    assert any(i.severity == Severity.WARNING and "no testable expectations" in i.message
               for s in report.stages for i in s.issues)


def test_contradicting_a_deployed_intent_needs_confirmation(kb):
    deployed = [IntentRecord(intent=Intent.model_validate(intent()))]
    opening = intent(description="Allow SSH", expectations=[
        {"src": "HR", "dst": "Finance", "protocol": "tcp", "port": 22, "expect": "allow"}])
    _, report = validate_intents([opening], kb, deployed)
    assert not report.passed and "would override deployed intent" in report.errors()[0].message
    _, report = validate_intents([{**opening, "priority": 200}], kb, deployed, allow_override=True)
    assert report.passed


def test_same_request_precedence(kb):
    raw = [intent(expectations=[{"src": "HR", "dst": "VPC5", "protocol": "tcp", "port": 443, "expect": "allow"},
                                {"src": "HR", "dst": "VPC5", "expect": "deny"}])]
    assert validate_intents(raw, kb, [])[1].passed  # one intent: its own expectations never conflict
    two = [intent(expectations=[{"src": "HR", "dst": "VPC5", "protocol": "tcp", "port": 443, "expect": "allow"}]),
           intent(expectations=[{"src": "HR", "dst": "VPC5", "expect": "deny"}])]
    assert validate_intents(two, kb, [])[1].passed  # the more specific one wins
    clash = [intent(expectations=[{"src": "HR", "dst": "VPC5", "protocol": "tcp", "port": 443, "expect": "allow"}]),
             intent(expectations=[{"src": "VPC4", "dst": "Finance", "protocol": "tcp", "expect": "deny"}])]
    assert not validate_intents(clash, kb, [])[1].passed
