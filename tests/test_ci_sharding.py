"""Exercise the CI runner against real CTest discovery and execution."""

from collections import Counter
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


RUNNER = Path(__file__).resolve().parents[1] / 'scripts' / 'run_ci_shard.py'


class CIShardingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='rut-ci-sharding-')
        self.addCleanup(self.directory.cleanup)
        self.build = Path(self.directory.name)

    def suite(self, count=11, failure=None):
        lines = []
        for index in range(count):
            name = f'case_{index}'
            marker = self.build / f'{name}.ran'
            code = f"open({str(marker)!r}, 'w').close(); raise SystemExit({int(index == failure)})"
            lines.append(f'add_test({name} "{sys.executable}" "-c" "{code}")')
            if index in (1, 6):
                lines.append(f'set_tests_properties({name} PROPERTIES LABELS "docker")')
            elif index % 2:
                lines.append(f'set_tests_properties({name} PROPERTIES RUN_SERIAL TRUE)')
            else:
                lines.append(f'set_tests_properties({name} PROPERTIES RESOURCE_LOCK "shared")')
        (self.build / 'CTestTestfile.cmake').write_text('\n'.join(lines) + '\n')

    def run_shard(self, shard, *extra):
        return subprocess.run([sys.executable, str(RUNNER), '--build-dir', str(self.build),
                               '--shard', str(shard), '--shards', '4', *extra],
                              capture_output=True, text=True)

    def test_partition_and_execution_exclude_docker_without_losing_tests(self):
        self.suite()
        expected = {f'case_{index}' for index in range(11) if index not in (1, 6)}
        executed = []
        for shard in range(1, 5):
            result = self.run_shard(shard)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads((self.build / 'ci-shard-inventory.json').read_text())
            names = report['shards'][shard - 1]
            markers = {p.stem for p in self.build.glob('*.ran')}
            self.assertEqual(markers, set(names))
            executed.extend(markers)
            for marker in self.build.glob('*.ran'):
                marker.unlink()
            self.assertTrue((self.build / 'ci-shard-results.xml').is_file())
        self.assertEqual(Counter(executed), Counter(expected))

    def test_failure_is_propagated(self):
        self.suite(failure=0)
        result = self.run_shard(1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('case_0', result.stdout)
        self.assertTrue((self.build / 'ci-shard-results.xml').is_file())

    def test_empty_partition_fails(self):
        self.suite(count=1)
        result = self.run_shard(1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('nonempty', result.stderr)
        self.assertFalse(list(self.build.glob('*.ran')))

    def test_invalid_shard_fails_before_running(self):
        self.suite()
        for shard in (0, 5):
            result = self.run_shard(shard)
            self.assertNotEqual(result.returncode, 0)
        self.assertFalse(list(self.build.glob('*.ran')))

    def test_automatic_fixture_overlap_fails_before_execution(self):
        self.suite()
        with (self.build / 'CTestTestfile.cmake').open('a') as stream:
            stream.write('set_tests_properties(case_0 PROPERTIES FIXTURES_SETUP shared)\n')
            stream.write('set_tests_properties(case_2 case_3 PROPERTIES FIXTURES_REQUIRED shared)\n')
        result = self.run_shard(1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('exactly once', result.stderr)
        self.assertFalse(list(self.build.glob('*.ran')))

    def test_discovery_error_fails_before_execution(self):
        (self.build / 'CTestTestfile.cmake').write_text('invalid_cmake_command()\n')
        result = self.run_shard(1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('CI shard failed', result.stderr)
        self.assertFalse(list(self.build.glob('*.ran')))

    def test_pr_scope_executes_only_selected_units(self):
        self.suite()
        with (self.build / 'CTestTestfile.cmake').open('a') as stream:
            stream.write('set_tests_properties(case_0 case_2 case_3 case_4 case_5 case_7 PROPERTIES LABELS unit)\n')
        selected = []
        for shard in range(1, 5):
            result = self.run_shard(shard, '--pr')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads((self.build / 'ci-shard-inventory.json').read_text())
            self.assertEqual(report['scope'], 'pr')
            self.assertIn('case_10', report['deferred_tests'])
            selected.extend(p.stem for p in self.build.glob('*.ran'))
            for marker in self.build.glob('*.ran'):
                marker.unlink()
        self.assertEqual(set(selected), {'case_0', 'case_2', 'case_3', 'case_4', 'case_5', 'case_7'})
        self.assertEqual(len(selected), len(set(selected)))

    def test_plan_only_does_not_execute_tests(self):
        self.suite()
        result = self.run_shard(1, '--plan-only')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(list(self.build.glob('*.ran')))


if __name__ == '__main__':
    unittest.main()
