"""Regression checks: missing or unrelated alerts must never satisfy validation."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from verify_ingestion import verify


class EvidenceVerifierTests(unittest.TestCase):
    def setUp(self):
        self.event = {
            'lab': {'run_id': 'unit-test', 'source': 'edr-lab-network-observer'},
            'timestamp': '2026-01-01T00:00:00+00:00',
            'event': {'action': 'connection_accepted'}, 'process': {'pid': 42},
            'source': {'ip': '127.0.0.1', 'port': 50000},
            'destination': {'ip': '127.0.0.1', 'port': 18080}}
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

    def test_contradictory_alert_fields_fail(self):
        for section, field, value in (
                ('destination', 'ip', '192.0.2.1'),
                ('destination', 'port', 443),
                ('source', 'ip', '192.0.2.2'),
                ('lab', 'source', 'unrelated'),
                ('event', 'action', 'unrelated')):
            with self.subTest(field=field, section=section):
                alert = copy.deepcopy(self.alert)
                alert['data'][section][field] = value
                with self.assertRaises(ValueError):
                    verify([self.event], [alert])

    def test_wrong_source_time_fails(self):
        self.alert['data']['timestamp'] = '2026-01-02T00:00:00+00:00'
        with self.assertRaises(ValueError):
            verify([self.event], [self.alert])

    def test_duplicate_source_fails(self):
        with self.assertRaises(ValueError):
            verify([self.event, self.event], [self.alert])

    def test_decoder_numeric_strings_match(self):
        for section, field in (('process', 'pid'), ('source', 'port'), ('destination', 'port')):
            self.alert['data'][section][field] = str(self.alert['data'][section][field])
        self.assertEqual(verify([self.event], [self.alert])['unique_connections'], 1)

    def test_missing_destination_fails(self):
        del self.alert['data']['destination']
        with self.assertRaises(ValueError):
            verify([self.event], [self.alert])


if __name__ == '__main__':
    unittest.main()
