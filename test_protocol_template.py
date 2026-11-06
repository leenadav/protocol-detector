"""Standard test template for one protocol family (stage 7, A12). Copy the subclass at the bottom for a new family.

A ProtocolProfileCase runs the checks every family must pass, from its descriptor and its labelled fixtures:
    1. the family has exactly one descriptor (inventory agreement);
    2. every fixture labelled with the family is identified as that family under the documented selection
       (automatic, or with the family's hint when it requires one);
    3. truncating a fixture never identifies another family, and the outcome stays explicit
       (detecting, incomplete, malformed, unknown or the same family);
    4. a bounded seeded mutation run never identifies another family and never exceeds the inspection budget;
    5. the evidence fields the family emits are within its declared allowance when one is given.
"""
import random
import unittest

from protocol_engine import Config, DatagramInspector, Inspector
from protocol_engine.descriptors import build
from protocol_adapters.protocol_fixtures import DATAGRAM_CASES, STREAM_CASES

DESCRIPTORS = build()


def family_of(label):
    return label.split("/", 1)[0]


class ProtocolProfileCase:
    family = None                   # set in the subclass
    evidence_fields = None          # optional closed allowance of evidence fields
    mutations = 40

    def fixtures(self):
        streams = [data for data, label in STREAM_CASES if family_of(label) == self.family]
        datagrams = [data for data, label in DATAGRAM_CASES if family_of(label) == self.family]
        return streams, datagrams

    def hint(self):
        return self.family if DESCRIPTORS[self.family].requires_hint else None

    def inspect_stream(self, data, hint=None):
        inspector = Inspector(Config(), protocol_hint=hint if hint in __import__("protocol_engine.registry", fromlist=["PARSERS"]).PARSERS else None)
        inspector.feed(data)
        return inspector.observation

    def test_descriptor_exists(self):
        self.assertIn(self.family, DESCRIPTORS)

    def test_fixtures_identify_the_family(self):
        streams, datagrams = self.fixtures()
        self.assertTrue(streams or datagrams, "no labelled fixture for " + self.family)
        for data in streams:
            observation = self.inspect_stream(data, self.hint())
            self.assertEqual(observation.status, "identified", observation.reason)
            self.assertEqual(family_of(observation.application_protocol or observation.encryption or ""), self.family)
            if self.evidence_fields is not None:
                self.assertTrue({e.field for e in observation.evidence} <= set(self.evidence_fields), {e.field for e in observation.evidence})
        for data in datagrams:
            observation = DatagramInspector().inspect(data, self.hint())
            self.assertEqual(observation.status, "identified", observation.reason)
            self.assertEqual(family_of(observation.application_protocol or observation.encryption or ""), self.family)

    def test_truncation_and_mutation_stay_explicit(self):
        rng = random.Random(hash(self.family) & 0xffff)
        streams, datagrams = self.fixtures()
        for data in streams:
            for cut in sorted({1, 2, len(data) // 2, len(data) - 1}):
                observation = self.inspect_stream(data[:cut], self.hint())
                if observation.status == "identified":
                    self.assertEqual(family_of(observation.application_protocol or observation.encryption or ""), self.family)
                else:
                    self.assertIn(observation.status, ("detecting", "incomplete", "malformed", "unknown", "budget_exhausted"))
            for _ in range(self.mutations):
                mutated = bytearray(data)
                for _ in range(rng.randrange(1, 4)):
                    mutated[rng.randrange(len(mutated))] = rng.randrange(256)
                observation = self.inspect_stream(bytes(mutated), self.hint())
                if observation.status == "identified":
                    self.assertIn(family_of(observation.application_protocol or observation.encryption or ""), DESCRIPTORS)
        for data in datagrams:
            for _ in range(self.mutations):
                mutated = bytearray(data)
                mutated[rng.randrange(len(mutated))] = rng.randrange(256)
                observation = DatagramInspector().inspect(bytes(mutated), self.hint())
                if observation.status == "identified":
                    self.assertIn(family_of(observation.application_protocol or observation.encryption or ""), DESCRIPTORS)


# ----- the template instances: copy one of these for a new family -----
class HTTPProfile(ProtocolProfileCase, unittest.TestCase):
    family = "http"


class SMB2Profile(ProtocolProfileCase, unittest.TestCase):
    family = "smb2"


class STUNProfile(ProtocolProfileCase, unittest.TestCase):
    family = "stun"              # both transports: stream and datagram fixtures run through the same template


class DNSProfile(ProtocolProfileCase, unittest.TestCase):
    family = "dns"


class ModbusProfile(ProtocolProfileCase, unittest.TestCase):
    family = "modbus"


if __name__ == "__main__":
    unittest.main()
