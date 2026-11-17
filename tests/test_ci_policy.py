"""Verify the PR/full policy and conservative handling of changed paths."""

import importlib.util
from pathlib import Path
import unittest


def module(name):
    path = Path(__file__).resolve().parents[1] / 'scripts' / (name + '.py')
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


plan = module('plan_ci')
runner = module('run_ci_shard')


class CIPolicyTests(unittest.TestCase):
    def test_documentation_and_ci_tooling_skip_native(self):
        for paths in (['docs/testing.md'], ['.github/workflows/ci.yml', 'scripts/plan_ci.py']):
            self.assertFalse(plan.classify(paths)['native'])

    def test_shared_native_inputs_and_unknown_paths_require_native(self):
        for path in ('src/runtime/timer.cc', 'include/rut/a.h', 'cmake/A.cmake',
                     'bench/CMakeLists.txt', 'tests/test_redis_resp3.py', 'unknown.cfg'):
            self.assertTrue(plan.classify([path])['native'], path)
        self.assertTrue(plan.classify(['src/runtime/timer.cc'])['models'])
        self.assertTrue(plan.classify(['src/runtime/timer.cc'])['format'])

    def test_full_matrix_preserves_all_configurations(self):
        full = plan.matrix(True)['include']
        self.assertEqual(len(full), 16)
        self.assertEqual({(x['compiler'], x['build_type']) for x in full},
                         {('clang', 'Debug'), ('clang', 'Release'), ('gcc', 'Debug'), ('gcc', 'Release')})
        self.assertEqual(len(plan.matrix(False)['include']), 4)

    def test_pr_selection_retains_units_smoke_and_changed_integration(self):
        def test(name, command, labels=()):
            return dict(name=name, command=command,
                        properties=[dict(name='LABELS', value=list(labels))])
        tests = [test('unit', ['/build/unit'], ['unit']),
                 test('test_integration.shard_0_of_2', ['/build/integration']),
                 test('redis', ['python3', '/source/tests/test_redis_resp3.py']),
                 test('changed_cpp', ['/build/test_foo']),
                 test('unrelated', ['python3', '/source/tests/test_other.py'])]
        self.assertEqual(runner.pr_selection(tests, ['tests/test_redis_resp3.py', 'tests/test_foo.cc']),
                         ['unit', 'test_integration.shard_0_of_2', 'redis', 'changed_cpp'])


if __name__ == '__main__':
    unittest.main()
