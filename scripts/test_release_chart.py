"""Exercise the actual Actions stamping commands with a generated-chart-shaped fixture."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'morten-olsen/homelab-dns-operator'
VERSION = '0.0.11'


def stamping_script(workflow):
    text = ROOT.joinpath('.github/workflows', workflow).read_text()
    block = re.search(r'^env:\n((?:  .*\n|\n)+)', text, re.M)
    env = dict(re.findall(r'^  ([A-Z_]+): (.*)$', block.group(1), re.M)) if block else {}
    values = {'github.repository': REPOSITORY, 'needs.version.outputs.new_version': VERSION}
    def evaluate(match):
        key = match.group(1).strip()
        if key.startswith('env.'):
            raw = env.get(key[4:], '')
            return re.sub(r'\$\{\{\s*([^}]+)\s*\}\}', lambda m: values[m.group(1).strip()], raw)
        return values[key]
    script = re.search(r'      - name: Update Chart version and image\n        run: \|\n((?:          .*\n|\n)+)', text).group(1)
    script = '\n'.join(line[10:] for line in script.splitlines())
    script = re.sub(r'\$\{\{\s*([^}]+)\s*\}\}', evaluate, script)
    return script


def stamp(workflow):
    script = stamping_script(workflow)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        chart = root / 'dist/chart'
        chart.mkdir(parents=True)
        chart.joinpath('Chart.yaml').write_text('apiVersion: v2\nname: dns-operator\nversion: 0.0.1\nappVersion: "0.0.1"\n')
        chart.joinpath('values.yaml').write_text('controllerManager:\n  replicas: 1\n  image:\n    repository: source/default\n    # tag: ""\n')
        subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], cwd=root, check=True)
        return chart.joinpath('Chart.yaml').read_text(), chart.joinpath('values.yaml').read_text()


class ChartStampingTests(unittest.TestCase):
    def test_release_and_pages_stamp_the_same_version_and_usable_image_repository(self):
        release = stamp('release.yml')
        pages = stamp('publish-helm.yml')
        self.assertEqual(release, pages)
        for metadata, values in [release, pages]:
            self.assertIn('version: ' + VERSION, metadata)
            self.assertIn('appVersion: "' + VERSION + '"', metadata)
            self.assertIn('repository: ghcr.io/' + REPOSITORY, values)
            self.assertNotIn('repository: /\n', values)


if __name__ == '__main__':
    unittest.main()
