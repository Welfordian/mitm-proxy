package store

import (
	"context"
	"testing"
)

func TestRepeaterMigrationCreatesTables(t *testing.T) {
	s := openTestStore(t)
	for _, table := range []string{"repeater_cases", "repeater_runs"} {
		var name string
		err := s.db.QueryRowContext(context.Background(), `SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
		if err != nil {
			t.Fatalf("expected table %s: %v", table, err)
		}
	}
}

func TestRepeaterCaseCRUDAndRunCascade(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	c, err := s.CreateRepeaterCase(ctx, RepeaterCase{
		Name:      "probe",
		Method:    "POST",
		URL:       "https://example.test/login",
		Headers:   map[string][]string{"X-Test": {"one"}},
		Body:      "a=1",
		TimeoutMS: 30000,
	})
	if err != nil {
		t.Fatalf("create case: %v", err)
	}
	if c.ID == "" {
		t.Fatal("expected generated case id")
	}
	cases, err := s.ListRepeaterCases(ctx, 10)
	if err != nil || len(cases) != 1 {
		t.Fatalf("list cases len=%d err=%v", len(cases), err)
	}
	c.Name = "probe updated"
	c.Headers["X-Test"] = []string{"two"}
	updated, err := s.UpdateRepeaterCase(ctx, c)
	if err != nil {
		t.Fatalf("update case: %v", err)
	}
	if updated.Name != "probe updated" || updated.Headers["X-Test"][0] != "two" {
		t.Fatalf("case was not updated: %+v", updated)
	}
	run, err := s.AddRepeaterRun(ctx, RepeaterRun{
		CaseID:          c.ID,
		Status:          201,
		DurationMS:      12,
		Bytes:           5,
		ResponseHeaders: map[string][]string{"Content-Type": {"text/plain"}},
		ResponseBody:    "hello",
	})
	if err != nil {
		t.Fatalf("add run: %v", err)
	}
	if run.ID == "" {
		t.Fatal("expected generated run id")
	}
	runs, err := s.ListRepeaterRuns(ctx, c.ID, 10)
	if err != nil || len(runs) != 1 {
		t.Fatalf("list runs len=%d err=%v", len(runs), err)
	}
	if runs[0].ResponseBody != "hello" || runs[0].ResponseHeaders["Content-Type"][0] != "text/plain" {
		t.Fatalf("run metadata not preserved: %+v", runs[0])
	}
	if err := s.DeleteRepeaterCase(ctx, c.ID); err != nil {
		t.Fatalf("delete case: %v", err)
	}
	runs, err = s.ListRepeaterRuns(ctx, c.ID, 10)
	if err != nil || len(runs) != 0 {
		t.Fatalf("expected deleted runs len=%d err=%v", len(runs), err)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir() + "/dashboard.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
