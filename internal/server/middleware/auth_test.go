package middleware

import "testing"

func TestHealthCheckIsWhitelistedAfterMTLS(t *testing.T) {
	if !MethodWhitelist["/grpc.health.v1.Health/Check"] {
		t.Fatal("health check must skip SSH metadata verification after mTLS host authorization")
	}
}
