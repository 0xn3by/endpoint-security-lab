"""Regression checks: missing or unrelated alerts must never satisfy validation."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from verify_ingestion import verify


class EvidenceVerifierTests(unittest.TestCase):
    def setUp(self):
        self.event = {'lab': {'run_id': 'unit-test'}, 'process': {'pid': 42}, 'source': {'port': 50000}}
        self.alert = {'rule': {'id': '100140'}, 'data': copy.deepcopy(self.event)}

    def test_matching_actual_shape(self):
        self.assertEqual(verify([self.event], [self.alert])['unique_connections'], 1)

    def test_missing_alert(self):
        with self.assertRaises(ValueError):
            verify([self.event], [])

    def test_other_run_cannot_satisfy(self):
        self.alert['data']['lab']['run_id'] = 'different-run'
        with self.assertRaises(ValueError):
            verify([self.event], [self.alert])

    def test_wrong_rule_cannot_satisfy(self):
        self.alert['rule']['id'] = '100130'
        with self.assertRaises(ValueError):
            verify([self.event], [self.alert])

    def test_missing_one_connection_fails(self):
        second = copy.deepcopy(self.event)
        second['source']['port'] = 50001
        with self.assertRaises(ValueError):
            verify([self.event, second], [self.alert])


if __name__ == '__main__':
    unittest.main()
