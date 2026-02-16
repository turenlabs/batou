package astflow

import "github.com/turenlabs/batou/internal/taint"

// FlowBuilder accumulates taint flows detected during analysis.
type FlowBuilder struct {
	flows    []taint.TaintFlow
	filePath string
}

// NewFlowBuilder creates a FlowBuilder for the given file.
func NewFlowBuilder(filePath string) *FlowBuilder {
	return &FlowBuilder{filePath: filePath}
}

// AddFlow records a taint flow from a tracked variable to a sink.
func (fb *FlowBuilder) AddFlow(ts *taintState, sink *taint.SinkDef, sinkLine int, scopeName string) {
	flow := taint.TaintFlow{
		Source:     *ts.source,
		Sink:       *sink,
		SourceLine: ts.sourceLine,
		SinkLine:   sinkLine,
		Steps:      ts.steps,
		FilePath:   fb.filePath,
		ScopeName:  scopeName,
		Confidence: ts.confidence,
	}
	fb.flows = append(fb.flows, flow)
}

// Flows returns all collected taint flows.
func (fb *FlowBuilder) Flows() []taint.TaintFlow {
	return fb.flows
}
