#!/usr/bin/env python3
# Copyright 2013-2026 chronicle.software; SPDX-License-Identifier: Apache-2.0
"""Run with Java 8 selected: python3 src/it/repeat-package.py NEW_WORK_DIRECTORY."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET
import zipfile

SOURCE = Path(__file__).resolve().parents[2]


class RepeatPackageTest(unittest.TestCase):
    def testPackageWithoutClean(self):
        version = subprocess.check_output(["./mvnw", "-version"], cwd=SOURCE, text=True)
        (WORK / "toolchain.txt").write_text(version)
        self.assertIn("Java version: 1.8.", version)
        for disabled in (False, True):
            case = WORK / ("overwrite-disabled" if disabled else "overwrite-enabled")
            shutil.copytree(SOURCE, case, ignore=shutil.ignore_patterns(".git", "target", "*.log"))
            if disabled:
                pom = case / "pom.xml"
                data = pom.read_bytes()
                setting = b"<overwriteExistingFiles>true</overwriteExistingFiles>"
                self.assertEqual(data.count(setting), 1)
                pom.write_bytes(data.replace(setting, setting.replace(b"true", b"false")))
            records = []
            for repeat in (False, True):
                log = "repeat-package.log" if repeat else "java8-verify.log"
                cmd = ["./mvnw", "-B", "-ntp"] + (["-DskipTests", "package"] if repeat else ["verify"]) + ["-l", log]
                with (case / (log + ".console")).open("wb") as output:
                    run = subprocess.run(cmd, cwd=case, stdout=output, stderr=subprocess.STDOUT)
                records.append({"command": cmd, "exit_code": run.returncode})
                (case / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
                text = (case / log).read_text()
                if disabled and repeat:
                    self.assertNotEqual(run.returncode, 0, "Overwrite-disabled repeat unexpectedly passed")
                    self.assertIn("moditect-maven-plugin:1.2.2.Final:add-module-info", text)
                    self.assertRegex(text, r"(?i)(already exists|FileAlreadyExistsException)")
                else:
                    self.assertEqual(run.returncode, 0, "Build/setup failed; see " + str(case / log))
                    self.assertIn("BUILD SUCCESS", text)
                if not repeat:
                    report = ET.parse(case / "target/failsafe-reports/TEST-net.openhft.hashing.AutomaticModuleNameIT.xml").getroot()
                    self.assertEqual([int(report.get(k, "0")) for k in ("tests", "failures", "errors", "skipped")], [3, 0, 0, 0])
                    project = ET.parse(case / "pom.xml").getroot()
                    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
                    artifact = project.findtext("m:artifactId", namespaces=ns)
                    artifact_version = project.findtext("m:version", namespaces=ns)
                    jar = case / "target" / f"{artifact}-{artifact_version}.jar"
                    shutil.copyfile(jar, case / "retained-verify.jar")
                elif not disabled:
                    def classes(path):
                        with zipfile.ZipFile(path) as archive:
                            return {n: archive.read(n) for n in archive.namelist() if n.endswith(".class")}
                    self.assertEqual(classes(case / "retained-verify.jar"), classes(jar))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    WORK = Path(sys.argv.pop(1)).resolve()
    if WORK == SOURCE or SOURCE in WORK.parents:
        sys.exit("Work directory must be outside the source tree")
    WORK.mkdir()
    unittest.main(verbosity=2)
