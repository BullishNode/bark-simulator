"""Real Git provenance controls; no wallet, daemon or native build."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from integration.sdk_source import fixture_source_receipt


class FixtureSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/dev/shm')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sdk = self.root / 'sdk'
        self.sdk.mkdir()
        self.module = self.sdk / 'testing/tests/bark_sdk/mod.rs'
        self.module.parent.mkdir(parents=True)
        self.module.write_text('mod existing;\n')
        self.git('init', '-q')
        self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
                 'commit', '-qm', 'baseline')
        self.head = self.git('rev-parse', 'HEAD')
        self.tree = self.git('rev-parse', 'HEAD^{tree}')
        self.expected = self.root / 'shared-harness.rs'
        self.expected.write_text('fn shared_fixture() {}\n')
        self.harness = self.module.with_name('simulator_vertical.rs')
        self.harness.write_bytes(self.expected.read_bytes())
        self.module.write_text('mod existing;\nmod simulator_vertical;\n')

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.sdk), *args], stderr=subprocess.PIPE, text=True).strip()

    def inspect(self, **kwargs):
        return fixture_source_receipt(self.sdk, kwargs.pop('commit', self.head),
                                      self.expected, **kwargs)

    def test_exact_new_sdk_and_overlay_are_recorded_without_historical_pin(self):
        receipt = self.inspect(expected_tree=self.tree)
        self.assertEqual(self.head, receipt['head'])
        self.assertEqual(self.tree, receipt['tree'])
        self.assertEqual(2, len(receipt['overlay_sha256']))
        self.assertEqual(receipt, self.inspect(expected_tree=self.tree))

    def test_wrong_commit_or_tree_refuses_even_with_matching_harness(self):
        for kwargs in ({'commit': '0' * 40}, {'expected_tree': '0' * 40}, {'commit': 'HEAD'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.inspect(**kwargs)

    def test_unlisted_source_overlay_refuses(self):
        (self.sdk / 'unexpected.rs').write_text('fn unexpected() {}\n')
        with self.assertRaisesRegex(ValueError, 'two-path'):
            self.inspect()

    def test_local_harness_substitution_refuses(self):
        self.harness.write_text('fn different_semantics() {}\n')
        with self.assertRaisesRegex(ValueError, 'shared source'):
            self.inspect()

    def test_overlay_changes_are_visible_even_when_git_status_is_unchanged(self):
        before = self.inspect()
        self.module.write_text(self.module.read_text() + '// source changed during run\n')
        after = self.inspect()
        self.assertNotEqual(before, after)

    def test_symlinked_harness_refuses(self):
        self.harness.unlink()
        self.harness.symlink_to(self.expected)
        with self.assertRaisesRegex(ValueError, 'regular source'):
            self.inspect()
