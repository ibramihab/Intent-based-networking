from ibn.intent.parser import RuleBasedParser
from ibn.intent.validation import validate_intents
from ibn.kb.state import IntentRecord
from ibn.models.intent import Intent, SolutionKind
from ibn.models.report import Severity
from tests.conftest import intent


def test_kb_is_consistent(kb):
    assert kb.check() == []


def test_kb_detects_p2p_convention_violation(kb):
    kb.interfaces["R2"]["Ethernet0/0"].ip = __import__("ipaddress").IPv4Interface("10.1.2.9/24")
    assert any("expected host part .2" in i.message for i in kb.check())


def test_schema_rejects_ports_on_icmp(kb):
    _, report = validate_intents([intent(services=[{"protocol": "icmp", "ports": [80]}])], kb, [])
    assert not report.passed
    assert "only valid for tcp/udp" in report.errors()[0].message


def test_unknown_group_is_semantic_error(kb):
    _, report = validate_intents([intent(dst={"group": "Sales"})], kb, [])
    assert "unknown group" in report.errors()[0].message


def test_names_are_canonicalised(kb):
    intents, report = validate_intents([intent(src={"group": "hr"}, dst={"host": "vpc5"})], kb, [])
    assert report.passed
    assert intents[0].source.group == "HR" and intents[0].destination.host == "VPC5"


def test_conflict_equal_priority_is_error_and_priority_resolves(kb):
    deployed = [IntentRecord(intent=Intent.model_validate(intent("deny", services=[{"protocol": "tcp", "ports": [80]}])),
                             solution=SolutionKind.ACL)]
    _, report = validate_intents([intent("permit", services=[{"protocol": "tcp", "ports": [80]}])], kb, deployed)
    assert not report.passed
    _, report = validate_intents([intent("permit", services=[{"protocol": "tcp", "ports": [80]}], priority=200)],
                                 kb, deployed)
    assert report.passed
    assert any(i.severity == Severity.WARNING and "wins by priority" in i.message for s in report.stages for i in s.issues)


def test_more_specific_rule_is_not_a_conflict(kb):
    raw = [intent("permit", services=[{"protocol": "tcp", "ports": [443]}]), intent("deny")]
    _, report = validate_intents(raw, kb, [])
    assert report.passed


def test_rule_parser_extracts_intent(kb):
    r = RuleBasedParser(kb).parse("Block HR from reaching Finance over ssh and https")
    assert r.intents[0]["action"] == "deny"
    assert r.intents[0]["source"] == {"group": "HR"}
    assert {"protocol": "tcp", "ports": [22]} in r.intents[0]["services"]
    assert RuleBasedParser(kb).parse("do something with HR").clarifications
