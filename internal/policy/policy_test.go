package policy

import (
	"net"
	"testing"
)

func TestEngineChecksBlockedRules(t *testing.T) {
	engine := New(
		[]int{25},
		[]string{"*.tracking.example", "malware.test"},
		[]string{"203.0.113.0/24", "10.0.0.5"},
	)

	if decision := engine.CheckPort(25); !decision.Blocked {
		t.Fatal("expected port 25 to be blocked")
	}

	if decision := engine.CheckDomain("pixel.tracking.example"); !decision.Blocked {
		t.Fatal("expected wildcard domain to be blocked")
	}

	if decision := engine.CheckDomain("malware.test"); !decision.Blocked {
		t.Fatal("expected exact domain to be blocked")
	}

	if decision := engine.CheckIP(net.ParseIP("203.0.113.9")); !decision.Blocked {
		t.Fatal("expected CIDR IP to be blocked")
	}

	if decision := engine.CheckIP(net.ParseIP("10.0.0.5")); !decision.Blocked {
		t.Fatal("expected exact IP to be blocked")
	}
}
