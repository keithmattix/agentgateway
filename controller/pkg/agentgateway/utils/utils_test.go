package utils

import "testing"

func TestLLMSectionName(t *testing.T) {
	tests := []struct {
		section  string
		listener string
		ok       bool
	}{
		{section: "https/llm", listener: "https", ok: true},
		{section: "llm", ok: false},
		{section: "/llm", ok: false},
		{section: "https/other", ok: false},
		{section: "https/foo/llm", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.section, func(t *testing.T) {
			listener, ok := LLMSectionName(tt.section)
			if ok != tt.ok || listener != tt.listener {
				t.Fatalf("LLMSectionName(%q) = (%q, %t), want (%q, %t)", tt.section, listener, ok, tt.listener, tt.ok)
			}
		})
	}
}

func TestLLMRouterRouteName(t *testing.T) {
	listenerKey := InternalGatewayName("default", "gateway", "https")
	if got, want := LLMRouterRouteName(listenerKey), "llm:request:default/gateway.https"; got != want {
		t.Fatalf("LLMRouterRouteName(%q) = %q, want %q", listenerKey, got, want)
	}
}
