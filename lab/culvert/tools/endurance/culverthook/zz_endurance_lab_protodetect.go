// Lab-only measurement hook for the PRO-540 endurance run, copied into the local Culvert clone as
// internal/protodetect/zz_endurance_lab.go. It exposes the detector engine's own counters (admission,
// refusals, the reserved and retained bytes) to the endurance hook in package main. Never shipped.
package protodetect

// EnduranceStats returns the engine's counters as plain numbers.
func (r *Real) EnduranceStats() map[string]int64 {
	s := r.engine.Stats()
	disabled := int64(0)
	if s.Disabled {
		disabled = 1
	}
	return map[string]int64{
		"active": s.Active, "admitted": s.Admitted, "refused": s.Refused, "panics": s.Panics,
		"disabled": disabled, "refused_memory": s.RefusedMemory, "refused_flow_limit": s.RefusedFlowLimit,
		"flow_allowance": s.FlowAllowance, "engine_allowance": s.EngineAllowance,
		"reserved_bytes": s.ReservedBytes, "retained_bytes": s.RetainedBytes,
	}
}
