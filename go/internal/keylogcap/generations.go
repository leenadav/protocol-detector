package keylogcap

// Generations is the coordinator's session identity (Milestone B, 2026-11-18): one counter per capture. A flow
// takes the counter's next value the first time it needs one (when the retained tier opens it, or when its
// session is published) and the value is released when the session is published or retracted, or when no
// tracked or retained flow holds the tuple any more. No (session id, generation) repeats within a capture, and
// the table holds only tuples with a flow in flight. A tuple's first session is not necessarily generation 0.
type Generations struct {
	next   int
	active map[string]int
}

// NewGenerations starts a capture's counter at 0.
func NewGenerations() *Generations { return &Generations{active: map[string]int{}} }

// Of is the generation of the flow holding the tuple, drawn from the counter on first use.
func (g *Generations) Of(sid string) int {
	if v, ok := g.active[sid]; ok {
		return v
	}
	v := g.next
	g.next++
	g.active[sid] = v
	return v
}

// Publish is the generation a session record carries; publishing releases it.
func (g *Generations) Publish(sid string) int {
	v := g.Of(sid)
	delete(g.active, sid)
	return v
}

// Release forgets the tuple's generation (a restart, a retraction, a retained flow no tracked flow holds).
func (g *Generations) Release(sid string) { delete(g.active, sid) }

// Held is the number of tuples holding a generation.
func (g *Generations) Held() int { return len(g.active) }
