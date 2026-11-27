package parsing

import "testing"

// PRO-596: Charge is Append's accounting without Append's allocation. A parser that reads a complete message in
// place instead of copying it into its accumulator charges exactly what the copy would have charged, so every
// denial, Used and Peak figure stays what it was.
func TestChargeAccountsExactlyAsAppend(t *testing.T) {
	for _, old := range []int{0, 8, 16, 48, 300} {
		for _, need := range []int{1, 8, 9, 42, 600, 1216, 1793, 4000, 20000, 40000} {
			for _, limit := range []int{0, 8, 64, 512, 1024, 2048, 4096, 8192, 1 << 20} {
				for _, used := range []int{0, 7, 100} {
					if used+old > limit {
						continue
					}
					buf := make([]byte, 0, old)
					if need <= len(buf) {
						continue
					}
					appended := &Credit{limit: limit, used: used + old, peak: used + old}
					charged := *appended
					_, appendErr := appended.Append(buf, make([]byte, need-len(buf)))
					chargeErr := charged.Charge(buf, need)
					if (appendErr == nil) != (chargeErr == nil) || *appended != charged {
						t.Fatalf("cap %d, need %d, limit %d, used %d: Append left %+v (err %v), Charge %+v (err %v)",
							old, need, limit, used, *appended, appendErr, charged, chargeErr)
					}
				}
			}
		}
	}
	var unlimited *Credit
	if err := unlimited.Charge(nil, 1<<20); err != nil {
		t.Fatalf("a nil Credit is unlimited, Charge returned %v", err)
	}
}

func TestChargeAllocatesNothing(t *testing.T) {
	c := NewCredit(1 << 20)
	buf := make([]byte, 4, 8)
	if n := testing.AllocsPerRun(100, func() { c.used = 8; _ = c.Charge(buf, 1800) }); n != 0 {
		t.Fatalf("Charge allocates %.0f times", n)
	}
}
