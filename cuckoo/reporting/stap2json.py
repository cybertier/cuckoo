import json
import logging
import re
import socket
from uuid import uuid1

from cuckoo.common.abstracts import Report

log = logging.getLogger(__name__)


class StapReporter(Report):

    def __init__(self):
        super(StapReporter, self).__init__()
        self.CWD = ""
        self.processes = []
        self.files_read = []
        self.files_written = []
        self.files_removed = []
        self.ipv4 = []
        self.ipv6 = []
        self.domains = []
        self.classifiers = []
        self.key_words = []
        self.whitelist = None

    def run(self, results):
        self.init()

        log.debug("start stap2json reporter")
        syscalls = open(self.analysis_path + "/logs/all.stap", "r").read()
        self.CWD = self.find_execution_dir_of_build_script(syscalls)
        log.debug("found execution dir: %s", self.CWD)
        self.parse_syscalls_to_artifacts(syscalls)
        log.debug("parsed syscalls to artifacts")

        log.debug("writing report to disk and serializing it")
        self.write_report({'files_written': list(set(self.files_written)),
                           'files_read': list(set(self.files_read)),
                           'files_removed': list(set(self.files_removed)),
                           'processes_created': list(set(self.processes)),
                           'domains_connected': list(set(self.domains)),
                           'hosts_connected': list(set(self.ipv4+self.ipv6))})
    def init(self):
        self.classifiers = [
            {
                "name": "files_removed",
                "key_word": ["unlink", "unlinkat", "rmdir"],
                "regexes": [
                    r"unlink\(\"(.*?)\"",
                    r"unlinkat\(.*?\"(.*?)\"",
                    r"rmdir\(\"(.*?)\"",
                ],
                "prepare": lambda ob: ob
                if ob.startswith("/")
                else self.CWD + "/" + str(ob),
            },
            {
                "name": "files_read",
                "key_word": ["openat"],
                "regexes": [
                    r"openat\(.*?\"(?P<filename>.*?)\".*?(?:O_RDWR|O_RDONLY).*?\)"
                ],
                "prepare": lambda ob: ob
                if ob.startswith("/")
                else self.CWD + "/" + str(ob),
            },
            {
                "name": "files_written",
                "key_word": ["openat", "rename", "link", "mkdir"],
                "regexes": [
                    r"openat\(.*?\"(.*?)\".*?(?:O_RDWR|O_WRONLY|O_CREAT|O_APPEND)",
                    r"(?:link|rename)\(\".*?\", \"(.*?)\"\)",
                    r"mkdir\(\"(.*?)\"",
                ],
                "prepare": lambda ob: ob
                if ob.startswith("/")
                else self.CWD + "/" + str(ob),
            },
            {
                "name": "hosts_connected",
                "key_word": ["connect"],
                "regexes": [r"connect\(.*?{AF_INET(?:6)?, (.*?), (.*?)},"],
                "prepare": lambda ob: str(ob[0]) + ":" + str(ob[1]),
            },
            {
                "name": "processes_created",
                "key_word": ["execve"],
                "regexes": [r"execve\(.*?\[(.*?)\]"],
                "prepare": lambda ob: ob.replace('"', "").replace(",", "").replace("'", ""),
            },
            {
                "name": "domains",
                "key_word": ["connect"],
                "regexes": [r"connect\(.*?{AF_INET(?:6)?, (.*?),"],
                "prepare": lambda ob: StapReporter.ip2domain(ob),
            },
        ]
        self.key_words = [
            key_word
            for classifier in self.classifiers
            for key_word in classifier["key_word"]
        ]

    @staticmethod
    def find_execution_dir_of_build_script(syscalls):
        exec_dir = re.findall(r"execve\(.*?\"-c\", \"(.*?)\/[^\"\/]+\"", syscalls)
        if exec_dir:
            return exec_dir[0]
        return ""

    def parse_syscalls_to_artifacts(self, syscalls):
        for classifier in self.classifiers:
            for regex in classifier["regexes"]:
                for line in syscalls.splitlines():
                    if self.line_is_relevant(line):
                        if re.search(regex, line):
                            self.parse_line_to_artifact(classifier, line, regex)

    def line_is_relevant(self, line):
        for word in self.key_words:
            if word in line:
                return True

    def parse_line_to_artifact(self, classifier, line, regex):
        if self.is_on_whitelist(
            classifier["prepare"](re.search(regex, line).group(1))
        ):
            return ""

        if classifier["name"] == "processes_created":
            self.processes.append(classifier["prepare"](re.search(regex, line).group(1)))

        if classifier["name"].startswith("files_"):
            name = classifier["prepare"](re.search(regex, line).group(1)).split("/")[-1]
            dir_str = "/".join(classifier["prepare"](re.search(regex, line).group(1)).split("/")[:-1]) or "/"
            if not name:
                name = classifier["prepare"](re.search(regex, line).group(1)).split("/")[-2]
                dir_str = "/".join(classifier["prepare"](re.search(regex, line).group(1)).split("/")[:-2]) or "/"
            if classifier["name"] == "files_removed":
                self.files_removed.append(dir_str+'/'+name)
            if classifier["name"] == "files_written":
                self.files_written.append(dir_str+'/'+name)
            if classifier["name"] == "files_read":
                self.files_read.append(dir_str+'/'+name)

        if classifier["name"] == "hosts_connected":
            ipv4_regex = r"([0-9]{1,3}\.){3}[0-9]{1,3}"
            if re.search(ipv4_regex, line):
                self.ipv4.append(re.search(regex, line).group(1))
            else:
                self.ipv6.append(re.search(regex, line).group(1))

        if classifier["name"] == "domains":
            ip = re.search(regex, line).group(1)
            domain_name = classifier["prepare"](ip)
            if domain_name:
                self.domains.append(domain_name)

    def is_on_whitelist(self, name):
        if not name:
            return True
            
        if not self.whitelist:
            self.whitelist = self.create_whitelist()

        return any([StapReporter.matches_whitelist_item(item, name) for item in self.whitelist])

    @staticmethod
    def matches_whitelist_item(item, name):
        without_wildcard = item.replace("*", "")
        if item.startswith("*") and item.endswith("*"):
            return without_wildcard in name
        if item.startswith("*"):
            return name.endswith(without_wildcard)
        if item.endswith("*"):
            return name.startswith(without_wildcard)
        return name == item

    @staticmethod
    def ip2domain(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except BaseException:
            return None

    def create_whitelist(self):
        whitelist = [
            "/root/.npm/_cacache*",  # npm cache
            "/root/.npm/_locks*",  # npm locks
            "/root/.npm/anonymous-cli-metrics.json",  # npm metrics
            "/root/.npm/_logs*",  # npm logs
        ]
        try:
            if self.task["custom"]:
                additional_whitelist = json.loads(self.task["custom"])
                whitelist.extend(additional_whitelist)
        except Exception as Argument:
            logging.exception("failed loading additional whitelist")
        return whitelist

    def write_report(self, artifacts):
        output_file = open(self.analysis_path + "/reports/artifacts.json", "w")
        json.dump(artifacts, output_file, indent=2)


if __name__ == "__main__":
    reporter = StapReporter()
    reporter.run(None)
