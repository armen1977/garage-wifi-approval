package main

import (
	"io"
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

func TestDeleteKeepsRouterOSRecordIDUnescaped(t *testing.T) {
	var requestURI string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURI = r.RequestURI
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	a := &app{router: client{base: server.URL, http: server.Client()}}
	if err := a.router.delete("/queue/simple/*A"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if requestURI != "/rest/queue/simple/*A" {
		t.Fatalf("request URI=%q", requestURI)
	}
}

func TestHiLinkSendSMS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/webserver/SesTokInfo":
			_, _ = io.WriteString(w, `<?xml version="1.0"?><response><SesInfo>SessionID=test</SesInfo><TokInfo>token</TokInfo></response>`)
		case "/api/sms/send-sms":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if r.Header.Get("Cookie") != "SessionID=test" {
				t.Fatalf("cookie=%q", r.Header.Get("Cookie"))
			}
			if r.Header.Get("__RequestVerificationToken") != "token" {
				t.Fatalf("token=%q", r.Header.Get("__RequestVerificationToken"))
			}
			body, _ := io.ReadAll(r.Body)
			for _, expected := range []string{"<Phone>+79281397663</Phone>", "<Content>Garage Wi-Fi code: 246810</Content>", "<Length>25</Length>"} {
				if !strings.Contains(string(body), expected) {
					t.Fatalf("body missing %q: %s", expected, body)
				}
			}
			_, _ = io.WriteString(w, `<?xml version="1.0"?><response>OK</response>`)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))
	defer server.Close()

	h := hiLinkClient{base: server.URL, http: server.Client()}
	if err := h.sendSMS("+79281397663", "Garage Wi-Fi code: 246810"); err != nil {
		t.Fatalf("send SMS: %v", err)
	}
}

func TestSMSStartKeepsPhoneOutOfResponse(t *testing.T) {
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/ip/hotspot/ip-binding" {
			t.Fatalf("router path=%s", r.URL.Path)
		}
		_, _ = io.WriteString(w, "[]")
	}))
	defer router.Close()

	modem := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/webserver/SesTokInfo":
			_, _ = io.WriteString(w, `<response><SesInfo>SessionID=test</SesInfo><TokInfo>token</TokInfo></response>`)
		case "/api/sms/send-sms":
			_, _ = io.WriteString(w, "<response>OK</response>")
		default:
			t.Fatalf("modem path=%s", r.URL.Path)
		}
	}))
	defer modem.Close()

	a := &app{
		cfg:           config{HiLinkURL: modem.URL, SMSPrefix: "Garage Wi-Fi code: ", SMSCodeTTL: 5 * time.Minute, SMSRetryDelay: 2 * time.Minute, SMSMaxPerHour: 2, SMSGlobalMaxPerHour: 20, LogPath: t.TempDir() + "/approval.log"},
		router:        client{base: router.URL, http: router.Client()},
		hiLink:        hiLinkClient{base: modem.URL, http: modem.Client()},
		pending:       map[string]request{},
		codes:         map[string]smsCode{},
		smsRateLimits: map[string]rateWindow{},
	}
	form := url.Values{"client_ip": {"192.168.60.253"}, "mac": {"AA:BB:CC:DD:EE:FF"}, "phone": {"+79281397663"}}
	req := httptest.NewRequest(http.MethodPost, "/sms/start", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := httptest.NewRecorder()
	a.smsStart(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	if strings.Contains(res.Body.String(), "+79281397663") {
		t.Fatalf("response exposes telephone number: %s", res.Body.String())
	}
	if len(a.codes) != 1 {
		t.Fatalf("code count=%d", len(a.codes))
	}
}
