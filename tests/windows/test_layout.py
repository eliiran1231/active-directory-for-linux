"""Offline file-layout checks; no subprocesses, network, .NET, or AD."""
import hashlib
import json
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
WINDOWS = ROOT / 'tests/windows'


class WindowsLayoutTests(unittest.TestCase):
    def test_project_links_resolve(self):
        for project in WINDOWS.rglob('*.csproj'):
            for node in ET.parse(project).iter():
                if node.tag not in {'ProjectReference', 'Compile', 'EmbeddedResource', 'None'}:
                    continue
                value = node.get('Include', '')
                if not value or any(c in value for c in '$*;'):
                    continue
                with self.subTest(project=str(project.relative_to(ROOT)), include=value):
                    self.assertTrue((project.parent / value.replace('\\', '/')).exists())

    def test_solution_projects_resolve(self):
        for path in re.findall(r'"([^"\r\n]+\.csproj)"', (ROOT / 'AdForLinux.sln').read_text()):
            with self.subTest(project=path):
                self.assertTrue((ROOT / path.replace('\\', '/')).is_file())

    def test_detached_source_pins_preserved(self):
        manifest = json.loads((WINDOWS / 'differential-replay/suite-wide/numeric-sites.json').read_text())
        for row in manifest['files']:
            with self.subTest(source=row['path']):
                self.assertEqual(row['sha256'], hashlib.sha256((ROOT / row['path']).read_bytes()).hexdigest())

    def test_existing_replay_sources_and_fixtures_preserved(self):
        base = WINDOWS / 'differential-replay/results'
        manifest = json.loads((base / 'manifest.json').read_text())
        for row in manifest['caseSources']:
            with self.subTest(source=row['path']):
                self.assertEqual(row['replaySourceSha256'], hashlib.sha256((ROOT / row['path']).read_bytes()).hexdigest())
        for row in manifest['fixtures']:
            with self.subTest(fixture=row['path']):
                self.assertEqual(row['sha256'], hashlib.sha256((base / row['path']).read_bytes()).hexdigest())


if __name__ == '__main__':
    unittest.main()
