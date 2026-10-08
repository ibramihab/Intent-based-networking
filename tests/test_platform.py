from ibn.platforms import get_platform
from ibn.platforms.configtree import ConfigTree, diff

IOS = get_platform("cisco_ios")

BASE = """hostname R1
interface Ethernet0/0
 ip address 10.1.2.1 255.255.255.0
interface Ethernet0/2
 description HR
 ip address 10.0.1.1 255.255.255.0
no ip domain lookup
"""


def test_tree_apply_modes_replacements_and_removals():
    tree = IOS.apply(ConfigTree.parse(BASE), [
        "interface e0/2", " ip access-group A in", " ip access-group B in", " description HR LAN",
        "no ip domain lookup", "ip domain lookup", "ip access-list extended X", " 10 permit ip any any", " 10 deny ip any any",
    ])
    text = tree.render()
    assert " ip access-group B in" in text and " ip access-group A in" not in text  # one ACL per direction
    assert " description HR LAN" in text and "description HR\n" not in text
    assert "no ip domain lookup" not in text and "ip domain lookup" in text  # negative setting flipped
    assert " 10 deny ip any any" in text and " 10 permit" not in text  # same sequence number replaces
    back = IOS.apply(tree, ["interface Ethernet0/2", " no ip access-group B in", " description HR",
                            "no ip access-list extended X", "no ip domain lookup"])
    assert diff(ConfigTree.parse(BASE), back) == ([], [])


def test_syntax_checker_accepts_varied_techniques():
    cmds = [
        "ip access-list extended IBN_A", " 10 permit tcp host 10.0.1.10 range 1000 2000 10.0.3.0 0.0.0.255 eq www 443",
        " 20 deny udp any any eq domain log", " 30 permit icmp any any echo-reply",
        "access-list 120 deny ip 10.0.1.0 0.0.0.255 any", "ip access-list standard IBN_S", " permit 10.0.1.0 0.0.0.255",
        "ip route 10.0.3.0 255.255.255.0 10.1.2.2", "ip route 192.0.2.0 255.255.255.0 Null0",
        "route-map IBN_PBR permit 10", " match ip address IBN_A", " set ip next-hop 10.1.2.2",
        "interface Ethernet0/2", " ip policy route-map IBN_PBR",
        "zone security IBN_IN", "class-map type inspect match-any IBN_CM", " match protocol https",
        "policy-map type inspect IBN_PM", " class type inspect IBN_CM", "  inspect", " class class-default", "  drop log",
        "zone-pair security IBN_ZP source IBN_IN destination self", " service-policy type inspect IBN_PM",
        "vlan 150", " name IBN_ISOLATED", "ip nat inside source list IBN_S interface Ethernet0/0 overload",
    ]
    assert IOS.syntax_check(cmds) == []


def test_syntax_checker_rejects_bad_config():
    msgs = " ".join(str(i) for i in IOS.syntax_check([
        "configure terminal", "show run", "ip access-group X in", "interface Ethernet0/1",
        " ip address 10.0.0.0 255.255.255.0", " bogus-command", "access-list 101 permit icmp any any eq 80",
        "ip access-list extended IBN_A", " deny tcp 10.0.1.0 0.0.3.255 any", " permit tcp any any eq 70000",
        "vlan 5000", "  orphan",
    ]))
    for fragment in ("'show'", "'ip access-group' is not a global command", "network or broadcast",
                     "'bogus-command' is not valid in interface mode", "port matching requires tcp/udp",
                     "non-contiguous wildcard", "out of range", "invalid VLAN id"):
        assert fragment in msgs, fragment


def test_dataplane_model_and_references():
    tree = IOS.apply(ConfigTree.parse(BASE), [
        "ip access-list extended IBN_A", " deny tcp any any eq 22", " permit ip any any",
        "interface Ethernet0/2", " ip access-group IBN_A in", " zone-member security IBN_Z",
        "ip route 192.0.2.0 255.255.255.0 Null0", "interface Ethernet0/0", " ip access-group MISSING out",
    ])
    m = IOS.dataplane(tree, "R1")
    assert m.interfaces["Ethernet0/2"].acl_in == "IBN_A" and m.interfaces["Ethernet0/2"].zone == "IBN_Z"
    assert m.acls["IBN_A"].entries[0].dst_port.values == [22]
    assert str(m.null_routes[0]) == "192.0.2.0/24"
    defined, refs = IOS.references(tree)
    missing = {(r.kind, r.name) for r in refs} - defined
    assert missing == {("acl", "MISSING"), ("zone", "IBN_Z")}


def test_unmodeled_features_are_reported():
    notes = IOS.unmodeled(["router ospf 1", " network 10.0.0.0 0.255.255.255 area 0", "ip route 10.0.3.0 255.255.255.0 10.1.2.2",
                           "interface Ethernet0/0", " ip nat inside", "ip access-list extended IBN_A", " permit ip any any"])
    assert notes == ["routing protocol (router ospf)", "static route (path changes are not simulated)",
                     "interface setting 'ip nat inside'"]


def test_read_only_commands():
    assert IOS.is_read_only("show ip access-lists IBN_A")
    assert IOS.is_read_only("show running-config | include IBN")
    assert not IOS.is_read_only("clear ip access-list counters")
    assert not IOS.is_read_only("show run | redirect flash:x")
