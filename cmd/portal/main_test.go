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
	if res.Code != http.StatusSeeOther { t.Fatalf("status=%d", res.Code) }
	if len(a.pending) != 1 { t.Fatalf("pending=%d", len(a.pending)) }
}

func TestAdminRejectsOutsideGarageLAN(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("192.168.50.0/24")
	a := &app{cfg: config{AdminUser: "master", AdminPassword: "secret", AdminCIDR: cidr}, pending: map[string]request{}}
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = "192.168.60.9:1234"
	req.SetBasicAuth("master", "secret")
	res := httptest.NewRecorder()
	a.admin(res, req)
	if res.Code != http.StatusNotFound { t.Fatalf("status=%d", res.Code) }
}
