from datetime import datetime, timezone

from netscanner.exporters import render_csv_report, render_json_report, render_text_report
from netscanner.models import ScanFinding, ScanMode, ScanReport


def sample_report():
    return ScanReport(
        target="127.0.0.1",
        mode=ScanMode.service,
        nmap_arguments="-sT -sV --version-light -T3 --reason",
        started_at=datetime(2026, 7, 7, 20, 0, tzinfo=timezone.utc),
        finished_at=datetime(2026, 7, 7, 20, 1, tzinfo=timezone.utc),
        findings=[
            ScanFinding(
                host="127.0.0.1",
                protocol="tcp",
                port=22,
                state="open",
                service="ssh",
                product="OpenSSH",
                version="9.6",
            )
        ],
    )


def test_text_report_contains_open_port():
    text = render_text_report(sample_report())
    assert "127.0.0.1:22/tcp open ssh" in text


def test_json_report_contains_findings():
    text = render_json_report(sample_report())
    assert '"findings"' in text
    assert '"OpenSSH"' in text


def test_csv_report_contains_header_and_row():
    text = render_csv_report(sample_report())
    assert "host,hostname,protocol,port,state,service,product,version,reason" in text
    assert "127.0.0.1,,tcp,22,open,ssh,OpenSSH,9.6," in text
