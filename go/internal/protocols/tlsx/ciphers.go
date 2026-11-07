package tlsx

// RFC 9325 classes of offered cipher suites (protocol_engine/tls_ciphers.py); suite numbers are never emitted.
var classOrder = []string{"null", "export", "anon", "rc4", "des", "64-bit-block"}

var weakSuites = map[uint16]string{
	0x0000: "null", 0x0001: "null", 0x0002: "null", 0x002c: "null", 0x002d: "null", 0x002e: "null", 0x003b: "null", 0x00b0: "null", 0x00b1: "null", 0x00b4: "null",
	0x00b5: "null", 0x00b8: "null", 0x00b9: "null", 0xc001: "null", 0xc006: "null", 0xc00b: "null", 0xc010: "null", 0xc015: "null", 0xc039: "null", 0xc03a: "null",
	0xc03b: "null", 0xc0b4: "null", 0xc0b5: "null",
	0x0003: "export", 0x0006: "export", 0x0008: "export", 0x000b: "export", 0x000e: "export", 0x0011: "export", 0x0014: "export", 0x0017: "export", 0x0019: "export", 0x0026: "export",
	0x0027: "export", 0x0028: "export", 0x0029: "export", 0x002a: "export", 0x002b: "export",
	0x0018: "anon", 0x001a: "anon", 0x001b: "anon", 0x0034: "anon", 0x003a: "anon", 0x0046: "anon", 0x006c: "anon", 0x006d: "anon", 0x0089: "anon", 0x009b: "anon",
	0x00a6: "anon", 0x00a7: "anon", 0x00bf: "anon", 0x00c5: "anon", 0xc016: "anon", 0xc017: "anon", 0xc018: "anon", 0xc019: "anon", 0xc046: "anon", 0xc047: "anon",
	0xc05a: "anon", 0xc05b: "anon", 0xc084: "anon", 0xc085: "anon",
	0x0004: "rc4", 0x0005: "rc4", 0x0020: "rc4", 0x0024: "rc4", 0x008a: "rc4", 0x008e: "rc4", 0x0092: "rc4", 0xc002: "rc4", 0xc007: "rc4", 0xc00c: "rc4",
	0xc011: "rc4", 0xc033: "rc4",
	0x0009: "des", 0x000c: "des", 0x000f: "des", 0x0012: "des", 0x0015: "des", 0x001e: "des", 0x0022: "des",
	0x0007: "64-bit-block", 0x000a: "64-bit-block", 0x000d: "64-bit-block", 0x0010: "64-bit-block", 0x0013: "64-bit-block", 0x0016: "64-bit-block", 0x001f: "64-bit-block", 0x0021: "64-bit-block", 0x0023: "64-bit-block", 0x0025: "64-bit-block",
	0x008b: "64-bit-block", 0x008f: "64-bit-block", 0x0093: "64-bit-block", 0xc003: "64-bit-block", 0xc008: "64-bit-block", 0xc00d: "64-bit-block", 0xc012: "64-bit-block", 0xc01a: "64-bit-block", 0xc01b: "64-bit-block", 0xc01c: "64-bit-block",
	0xc034: "64-bit-block",
}

// offeredWeakClasses returns the classes present in an even-length suite vector, in classOrder.
func offeredWeakClasses(suites []byte) []string {
	present := map[string]bool{}
	for i := 0; i+1 < len(suites); i += 2 {
		if label, ok := weakSuites[uint16(suites[i])<<8|uint16(suites[i+1])]; ok {
			present[label] = true
		}
	}
	var out []string
	for _, label := range classOrder {
		if present[label] {
			out = append(out, label)
		}
	}
	return out
}
