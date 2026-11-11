"""Synthetic policy examples, NOT execution/validation of the PowerShell implementation.
The Windows PS5.1 helper must independently be exercised against these same cases.
"""
import copy
import json
import unittest

EXECUTION = 'a' * 32

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate')
        result[key] = value
    return result

def envelope(lines):
    rows = [json.loads(line, object_pairs_hook=unique_object) for line in lines]
    if len(rows) < 3 or [r['kind'] for r in rows[:2]] != ['begin', 'live-scalar-review'] or rows[-1]['kind'] != 'end':
        raise ValueError('envelope')
    if any(r['execution'] != rows[0]['execution'] for r in rows):
        raise ValueError('execution')
    observations = rows[2:-1]
    if any(r['kind'] != 'observation' or r['sequence'] != i + 1 for i, r in enumerate(observations)):
        raise ValueError('sequence')
    if rows[-1]['observations'] != len(observations):
        raise ValueError('end count')
    return observations

def admitted(snapshot):
    if not snapshot.get('replayable'):
        return None
    kind, value = snapshot['type'], snapshot['value']
    if kind == 'null' and value is None:
        return snapshot
    if kind == 'boolean' and type(value) is bool:
        return snapshot
    if kind in {'int32', 'int64', 'enum-int64'} and type(value) is int and -(2**63) <= value < 2**63:
        return snapshot
    # A subset sufficient for these examples; production has a larger finite list.
    if kind == 'exception-type' and value in {'System.ArgumentException', 'ArgumentException'}:
        return snapshot
    return None

def fixture():
    rows = [dict(kind='begin'), dict(kind='live-scalar-review'), dict(kind='observation', sequence=1), dict(kind='end', observations=1)]
    return [dict(row, execution=EXECUTION) for row in rows]

def encode(rows):
    return [json.dumps(r) for r in rows]

class SyntheticPolicyExamples(unittest.TestCase):
    def test_matching_scalars_admitted(self):
        value = dict(type='int32', value=42, replayable=True)
        self.assertEqual(admitted(value), admitted(copy.deepcopy(value)))

    def test_mismatching_scalars_both_admitted(self):
        self.assertNotEqual(admitted(dict(type='int32', value=1, replayable=True)), admitted(dict(type='int32', value=2, replayable=True)))

    def test_secret_string_withheld(self):
        self.assertIsNone(admitted(dict(type='string', value='synthetic-not-a-real-secret', replayable=True)))

    def test_redacted_withheld(self):
        self.assertIsNone(admitted(dict(type='redacted', value=None, replayable=False)))

    def test_unknown_exception_withheld(self):
        self.assertIsNone(admitted(dict(type='exception-type', value='SecretNamedException', replayable=True)))

    def test_non_integral_value_withheld(self):
        self.assertIsNone(admitted(dict(type='int64', value=1.5, replayable=True)))

    def test_complete_envelope_admitted(self):
        self.assertEqual(len(envelope(encode(fixture()))), 1)

    def test_malformed_json_rejected(self):
        with self.assertRaises(ValueError): envelope(['{'])

    def test_duplicate_field_rejected(self):
        with self.assertRaises(ValueError): envelope(['{"kind":"begin","kind":"end"}'])

    def test_wrong_execution_rejected(self):
        rows = fixture(); rows[2]['execution'] = 'b' * 32
        with self.assertRaises(ValueError): envelope(encode(rows))

    def test_wrong_sequence_rejected(self):
        rows = fixture(); rows[2]['sequence'] = 2
        with self.assertRaises(ValueError): envelope(encode(rows))

    def test_wrong_end_count_rejected(self):
        rows = fixture(); rows[-1]['observations'] = 2
        with self.assertRaises(ValueError): envelope(encode(rows))

    def test_missing_review_rejected(self):
        rows = fixture(); del rows[1]
        with self.assertRaises(ValueError): envelope(encode(rows))

if __name__ == '__main__': unittest.main()
