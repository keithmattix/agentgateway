package plugins

import (
	"testing"

	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestGatewayPolicyTargetLLMSection(t *testing.T) {
	section := gwv1.SectionName("https/llm")
	target := gatewayPolicyTarget("default", "gateway", &section, nil)

	route := target.GetRoute()
	if route == nil {
		t.Fatalf("expected %q to target the generated LLM route, got %#v", section, target.GetKind())
	}
	if got, want := route.Name, "llm:request:default/gateway.https"; got != want {
		t.Fatalf("route name = %q, want %q", got, want)
	}
	if route.Namespace != "internal" || route.Kind != "" || route.RouteRule != nil {
		t.Fatalf("unexpected generated LLM route target: %#v", route)
	}
}

func TestGatewayPolicyTargetListenerSection(t *testing.T) {
	section := gwv1.SectionName("https")
	target := gatewayPolicyTarget("default", "gateway", &section, nil)

	if target.GetGateway() == nil {
		t.Fatalf("expected normal listener section to remain a Gateway target, got %#v", target.GetKind())
	}
}
