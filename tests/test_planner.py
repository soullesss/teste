from netscanner.models import ScanMode, ScanRequest
from netscanner.scanner import build_nmap_plan


def test_tcp_plan_uses_tcp_connect():
    request = ScanRequest(target="127.0.0.1", ports="22,80", mode=ScanMode.tcp)
    plan = build_nmap_plan(request, privileged=False)

    assert "-sT" in plan.nmap_arguments
    assert plan.command_preview == "nmap -sT -T3 --reason -p 22,80 127.0.0.1"


def test_syn_plan_falls_back_without_privilege():
    request = ScanRequest(target="127.0.0.1", ports="22", mode=ScanMode.syn)
    plan = build_nmap_plan(request, privileged=False)

    assert "-sT" in plan.nmap_arguments
    assert plan.warnings


def test_syn_plan_uses_syn_with_privilege():
    request = ScanRequest(target="127.0.0.1", ports="22", mode=ScanMode.syn)
    plan = build_nmap_plan(request, privileged=True)

    assert "-sS" in plan.nmap_arguments
    assert not plan.warnings
