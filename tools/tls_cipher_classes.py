"""Derive the weak TLS cipher-suite classes (v0.64) from a local copy of the IANA registry.

Usage: python3 -B tools/tls_cipher_classes.py tls-parameters-4.csv

Reads the "TLS Cipher Suites" CSV (https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv),
never the network, and prints the table that protocol_engine/tls_ciphers.py embeds. Each assigned suite gets
at most one class, the first rule its IANA name matches, in this order (RFC 9325 section 4.1, BCP 195):
null (no encryption, including the RFC 9150 integrity-only suites), export, anon (no authentication),
rc4, des (single DES, 56 bits), 64-bit-block (3DES-EDE and IDEA: Sweet32).
"""
import csv
import sys

RULES = (("null", ("_WITH_NULL_", "TLS_NULL_WITH_NULL_NULL", "TLS_SHA256_SHA256", "TLS_SHA384_SHA384")),
         ("export", ("_EXPORT",)),
         ("anon", ("_anon_",)),
         ("rc4", ("_RC4_",)),
         ("des", ("_WITH_DES_CBC_", "_DES40_")),
         ("64-bit-block", ("_3DES_EDE_", "_WITH_IDEA_")))


def classes(rows):
    table = {}
    for row in rows:
        value, name = row["Value"], row["Description"]
        if "-" in value or not name.startswith("TLS_") or name.endswith("_SCSV"):
            continue                                      # ranges, Unassigned/Reserved, signalling values
        first, second = (int(part, 16) for part in value.split(","))
        for label, needles in RULES:
            if any(needle in name for needle in needles):
                table[first << 8 | second] = label
                break
    return table


def main(path):
    with open(path, newline="", encoding="utf-8") as handle:
        table = classes(csv.DictReader(handle))
    for label, _ in RULES:
        codes = sorted(code for code, value in table.items() if value == label)
        print("    # %s (%d)" % (label, len(codes)))
        for start in range(0, len(codes), 10):
            print("    " + " ".join("0x%04x: %r," % (code, label) for code in codes[start:start + 10]))


if __name__ == "__main__":
    main(sys.argv[1])
