package store

import (
	"context"
	"encoding/json"
	"testing"
)

func TestAINotesCreateListDeleteAndFilter(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	first, err := st.CreateAINote(ctx, AINote{
		Kind:       "explanation",
		TargetType: "traffic",
		TargetID:   "flow-1",
		ScopeID:    "scope-1",
		Model:      "gpt-test",
		PromptHash: "abc",
		Title:      "Traffic explanation",
		Summary:    "summary",
		Content:    json.RawMessage(`{"summary":"summary","interesting_observations":[]}`),
	})
	if err != nil {
		t.Fatalf("create first note: %v", err)
	}
	if _, err := st.CreateAINote(ctx, AINote{
		Kind:       "test_suggestions",
		TargetType: "repeater_case",
		TargetID:   "case-1",
		Title:      "Suggestions",
		Content:    json.RawMessage(`{"summary":"out of scope"}`),
	}); err != nil {
		t.Fatalf("create second note: %v", err)
	}

	trafficNotes, err := st.ListAINotes(ctx, AINoteFilter{TargetType: "traffic", ScopeID: "scope-1"})
	if err != nil {
		t.Fatalf("list traffic notes: %v", err)
	}
	if len(trafficNotes) != 1 || trafficNotes[0].ID != first.ID || trafficNotes[0].Summary != "summary" {
		t.Fatalf("unexpected traffic notes: %+v", trafficNotes)
	}

	outOfScope, err := st.ListAINotes(ctx, AINoteFilter{ScopeID: "__out_of_scope__"})
	if err != nil {
		t.Fatalf("list out-of-scope notes: %v", err)
	}
	if len(outOfScope) != 1 || outOfScope[0].TargetType != "repeater_case" {
		t.Fatalf("unexpected out-of-scope notes: %+v", outOfScope)
	}

	if err := st.DeleteAINote(ctx, first.ID); err != nil {
		t.Fatalf("delete note: %v", err)
	}
	remaining, err := st.ListAINotes(ctx, AINoteFilter{})
	if err != nil {
		t.Fatalf("list remaining notes: %v", err)
	}
	if len(remaining) != 1 || remaining[0].ID == first.ID {
		t.Fatalf("unexpected remaining notes: %+v", remaining)
	}
}

func TestPurgeResearchDataRemovesAINotes(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	if _, err := st.CreateAINote(ctx, AINote{TargetType: "traffic", TargetID: "flow-1", Content: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("create note: %v", err)
	}
	if err := st.PurgeResearchData(ctx, false); err != nil {
		t.Fatalf("purge research data: %v", err)
	}
	notes, err := st.ListAINotes(ctx, AINoteFilter{})
	if err != nil {
		t.Fatalf("list notes: %v", err)
	}
	if len(notes) != 0 {
		t.Fatalf("expected ai notes to be purged, got %+v", notes)
	}
}
