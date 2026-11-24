package signatures

// cost.go bounds the compile and run cost of signature patterns (PRO-51 SEC-SIG-2 and SEC-SIG-1).
//
// SEC-SIG-2: a 512-character pattern can compile to hundreds of thousands of RE2 instructions (a bounded repeat
// x{0,n} is n nested copies of x), and a document holds up to 4096 signatures of 64 conditions each, so loading
// a hostile set was unbounded in time and memory. estimateInsts computes, on the parsed pattern tree and before
// the Go expression is built or regexp.Compile runs, an upper bound of the instruction count of the program
// regexp.Compile produces for the expression compileTree writes (the model below follows regexp/syntax's
// Simplify and Compile; TestEstimateBoundsTheCompiledProgram checks the bound against the real program). The
// arithmetic saturates and the walk stops as soon as the running count passes the limit, so the estimate itself
// costs at most one pass over the tree. A pattern above maxPatternInsts, or one that would take the set past
// maxSetInsts, is refused as not ported: the reference answers, and a refusal is never a positive result.
//
// SEC-SIG-1: see Work (signatures.go) and signatureWorkLimit in the engine (inspector.go).

// Instruction caps approved for PRO-51 (Hermes, PRO-160 and PRO-170 measurements).
const (
	maxPatternInsts = 10000  // one pattern-match condition
	maxSetInsts     = 100000 // every pattern-match condition of a signature set, cumulative in document order
)

// satAdd and satMul are saturating at limit+1: any value above limit means "over the limit".
func satAdd(a, b, limit int) int {
	if a > limit || b > limit || a+b > limit {
		return limit + 1
	}
	return a + b
}

func satMul(a, b, limit int) int {
	if a == 0 || b == 0 {
		return 0
	}
	if a > limit || b > limit || a > limit/b {
		return limit + 1
	}
	return a * b
}

// estimateInsts is an upper bound of len(prog.Inst) for the pattern's compiled expression, or a value above limit
// when the bound passes limit (the walk stops there).
func estimateInsts(tree []node, limit int) int {
	// The program always holds the InstFail at index 0 and the final InstMatch.
	return satAdd(2, seqInsts(tree, limit), limit)
}

// seqInsts bounds a concatenation: the sum of its items, or one InstNop when it is empty.
func seqInsts(seq []node, limit int) int {
	if len(seq) == 0 {
		return 1
	}
	total := 0
	for i := range seq {
		total = satAdd(total, nodeInsts(&seq[i], limit), limit)
		if total > limit {
			return total
		}
	}
	return total
}

func nodeInsts(n *node, limit int) int {
	switch n.op {
	case opLiteral, opNotLiteral, opAny, opIn:
		return 1 // one InstRune (an empty class is OpNoMatch: no instruction)
	case opAt:
		if n.at == atEnd {
			return 3 // \n?\z: InstAlt, InstRune, InstEmptyWidth
		}
		return 1 // one InstEmptyWidth
	case opSubpattern:
		return seqInsts(n.body, limit) // (?:...) adds no instruction
	case opBranch:
		// n-1 InstAlt join n alternatives; the parser's factoring and class merging only remove instructions.
		total := len(n.branches)
		for _, b := range n.branches {
			total = satAdd(total, seqInsts(b, limit), limit)
			if total > limit {
				return total
			}
		}
		return total
	case opRepeat, opPossessive:
		return repeatInsts(seqInsts(n.body, limit), n.min, n.max, limit)
	}
	return 1 // assertions, backreferences and (?!) are refused before compilation
}

// repeatInsts bounds body{min,max} after Simplify, including writeRepeat's split into pieces of at most 1000:
// x{n} is n copies of x, x{n,m} adds m-n nested x? (one InstAlt each), x{n,} ends in x+ or x* (at most two
// more instructions). The split keeps the total number of copies, so the same bound holds for it.
func repeatInsts(body, min, max, limit int) int {
	if body > limit {
		return body
	}
	if max == maxRepeat {
		return satAdd(satMul(min+1, body, limit), 2, limit)
	}
	if max == 0 {
		return 1 // x{0} is an empty match
	}
	return satAdd(satMul(max, body+1, limit), 1, limit)
}

// instBudget is the cumulative instruction budget of one signature set (maxSetInsts).
type instBudget struct{ used int }

// charge admits a pattern of insts instructions or reports why it is refused; nothing is charged on a refusal.
func (b *instBudget) charge(insts int) error {
	if insts > maxPatternInsts {
		return &notPortedError{"pattern compiles to more than 10000 instructions (SEC-SIG-2 cap)"}
	}
	if b != nil {
		if b.used+insts > maxSetInsts {
			return &notPortedError{"signature set compiles to more than 100000 instructions (SEC-SIG-2 cap)"}
		}
		b.used += insts
	}
	return nil
}
