package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRequestDoesNotCallRouter(t *testing.T) {
	a := &app{cfg: config{RequestTTL: time.Minute, LogPath: t.TempDir() + "/approval.log"}, pending: map[string]request{}}
	form := url.Values{"client_ip": {"192.168.60.253"}, "mac": {"AA:BB:CC:DD:EE:FF"}}
	req := httptest.NewRequest(http.MethodPost, "/request", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := httptest.NewRecorder()
	a.createRequest(res, req)
	if res.Code != http.StatusSeeOther {
		t.Fatalf("status=%d", res.Code)
	}
	if len(a.pending) != 1 {
		t.Fatalf("pending=%d", len(a.pending))
	}
}

func TestAdminRejectsOutsideGarageLAN(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("192.168.50.0/24")
	a := &app{cfg: config{AdminUser: "master", AdminPassword: "secret", AdminCIDRs: []*net.IPNet{cidr}}, pending: map[string]request{}}
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = "192.168.60.9:1234"
	req.SetBasicAuth("master", "secret")
	res := httptest.NewRecorder()
	a.admin(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("status=%d", res.Code)
	}
}

func TestAdminAcceptsGarageAndHomeLAN(t *testing.T) {
	_, garage, _ := net.ParseCIDR("192.168.50.0/24")
	_, home, _ := net.ParseCIDR("192.168.88.0/24")
	a := &app{cfg: config{AdminCIDRs: []*net.IPNet{garage, home}}}
	for _, address := range []string{"192.168.50.15", "192.168.88.15"} {
		if !a.adminIPAllowed(net.ParseIP(address)) {
			t.Fatalf("administrator IP %s was rejected", address)
		}
	}
	if a.adminIPAllowed(net.ParseIP("192.168.60.15")) {
		t.Fatal("guest IP was accepted")
	}
}

func TestGrantRejectsMismatchedHotspotHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/ip/hotspot/host" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`[{"address":"192.168.60.254","mac-address":"AA:BB:CC:DD:EE:FF"}]`))
	}))
	defer server.Close()
	a := &app{cfg: config{GaragePassword: "secret"}, router: client{base: server.URL, http: server.Client()}}
	_, err := a.grant(request{ClientIP: "192.168.60.254", MAC: "11:22:33:44:55:66"})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("err=%v", err)
	}
}
