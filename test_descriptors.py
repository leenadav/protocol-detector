"""Stage 7 (A12): one capability definition per protocol family, validated against every table it derives from."""
import unittest

from protocol_engine.catalog import supported_protocols
from protocol_engine.descriptors import SELECTIONS, InventoryError, build, validate_inventory
from protocol_engine.registry import PARSERS


class DescriptorTests(unittest.TestCase):
    def test_every_public_family_has_one_descriptor_and_the_tables_agree(self):
        descriptors = build()
        self.assertEqual(set(descriptors), {entry.family for entry in supported_protocols()})
        for descriptor in descriptors.values():
            self.assertEqual(len(descriptor.transports), len(descriptor.selection))
            self.assertEqual(len(descriptor.transports), len(descriptor.implementation))
            self.assertTrue(set(descriptor.selection) <= set(SELECTIONS), descriptor.family)
            self.assertTrue(descriptor.profile and descriptor.scope, descriptor.family)
        summary = validate_inventory()
        self.assertEqual(summary["families"], len(descriptors))
        self.assertGreater(summary["hint_only"], 0)
        hint_only = {name for name, d in descriptors.items() if d.requires_hint}
        self.assertTrue(all(d.requires_hint for d in descriptors.values() if "hint" in d.selection))
        self.assertTrue(all("tcp" in descriptors[n].transports or "udp" in descriptors[n].transports for n in hint_only))

    def test_a_missing_or_duplicate_definition_fails_the_check(self):
        from unittest.mock import patch
        import protocol_engine.descriptors as module
        from protocol_engine.catalog import ProtocolSupport
        extra = supported_protocols() + (ProtocolSupport("ghost", ("tcp",), "x", "no parser anywhere"),)
        with patch.object(module, "supported_protocols", lambda: extra):
            with self.assertRaisesRegex(InventoryError, "ghost"):
                build()
        duplicate = supported_protocols() + (supported_protocols()[0],)
        with patch.object(module, "supported_protocols", lambda: duplicate):
            with self.assertRaisesRegex(InventoryError, "duplicate"):
                build()
        orphan = dict(PARSERS, orphan=PARSERS["tls"])
        with patch.object(module, "PARSERS", orphan):
            with self.assertRaisesRegex(InventoryError, "orphan"):
                build()


if __name__ == "__main__":
    unittest.main()
