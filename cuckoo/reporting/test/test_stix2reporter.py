from ..stix2reporter import Stix2
from pathlib import Path


def test_stuff():
    data = Path(__file__).with_name("all.stap")
    syscalls = data.open("r").read()
    reporter = Stix2()
    reporter.init()
    reporter.CWD = reporter.find_execution_dir_of_build_script(syscalls)
    reporter.parse_syscalls_to_stix(syscalls)
    assert len(reporter.ipv4) == 13
    assert len(reporter.ipv6) == 12
    assert len(reporter.domains) == 1
    assert len(reporter.files_read) == 1109
    assert len(reporter.files_removed) == 8
    assert len(reporter.files_written) == 292
    assert len(reporter.processes) == 5
