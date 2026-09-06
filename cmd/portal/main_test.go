package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestRouterClientReusesOneConnection(t *testing.T) {
	var mu sync.Mutex
	connections := map[net.Conn]struct{}{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = io.WriteString(w, `[]`)
		case http.MethodPut, http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("method=%s", r.Method)
		}
	}))
	server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateNew {
			mu.Lock()
			connections[conn] = struct{}{}
			mu.Unlock()
		}
	}
	server.Start()
	defer server.Close()

	httpClient := newRouterHTTPClient()
	defer httpClient.CloseIdleConnections()
	router := client{base: server.URL, http: httpClient}
	var records []map[string]any
	if err := router.get("/queue/simple", &records); err != nil {
		t.Fatalf("get: %v", err)
	}
	if err := router.put("/queue/simple", map[string]string{"name": "test"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := router.delete("/queue/simple/*1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	mu.Lock()
	count := len(connections)
	mu.Unlock()
	if count != 1 {
		t.Fatalf("connections=%d, want 1", count)
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

func TestHomeShowsEqualMasterAndSMSButtons(t *testing.T) {
	a := &app{}
	req := httptest.NewRequest(http.MethodGet, "/?client_ip=192.168.60.253&mac=AA:BB:CC:DD:EE:FF", nil)
	res := httptest.NewRecorder()
	a.home(res, req)

	body := res.Body.String()
	for _, expected := range []string{
		`<button>Запросить доступ у мастера</button>`,
		`<button>Войти по SMS-коду</button>`,
		`<div class="actions">`,
		`Срок хранения записей - 365 дней.`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("home page missing %q: %s", expected, body)
		}
	}
	if strings.Contains(body, `<a href="/sms`) {
		t.Fatalf("SMS entry must be a button, not a text link: %s", body)
	}
}

func TestNormalizePhone(t *testing.T) {
	for input, expected := range map[string]string{
		"9281234567":       "+79281234567",
		"89281234567":      "+79281234567",
		"+7 928 123-45-67": "+79281234567",
		"+447911123456":    "+447911123456",
		"not a number":     "",
	} {
		if actual := normalizePhone(input); actual != expected {
			t.Fatalf("normalizePhone(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestSMSPagesPreventDuplicateSubmission(t *testing.T) {
	a := &app{cfg: config{HiLinkURL: "http://192.168.8.1"}}
	start := httptest.NewRecorder()
	a.sms(start, httptest.NewRequest(http.MethodGet, "/sms?client_ip=192.168.60.253&mac=AA:BB:CC:DD:EE:FF", nil))
	if !strings.Contains(start.Body.String(), `class="phone"><span>+7</span>`) || !strings.Contains(start.Body.String(), `textContent='Отправляем...'`) {
		t.Fatalf("SMS start page is missing the Russian prefix or submission guard: %s", start.Body.String())
	}

	verify := httptest.NewRecorder()
	a.renderSMSVerify(verify, request{ClientIP: "192.168.60.253", MAC: "AA:BB:CC:DD:EE:FF"}, "+79281234567", smsCode{ExpiresAt: time.Now().Add(time.Minute)})
	if !strings.Contains(verify.Body.String(), `textContent='Проверяем...'`) {
		t.Fatalf("SMS verification page is missing a submission guard: %s", verify.Body.String())
	}
}

func TestLogEventWritesDailyAuditFile(t *testing.T) {
	dir := t.TempDir()
	a := &app{cfg: config{LogPath: filepath.Join(dir, "approval.log")}}
	a.logEvent(map[string]any{"type": "access_granted", "method": "sms", "phone_e164": "+79281234567"})

	name := "approval-" + time.Now().UTC().Format("2006-01-02") + ".jsonl"
	contents, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	var event map[string]any
	if err := json.Unmarshal(contents, &event); err != nil {
		t.Fatal(err)
	}
	if event["phone_e164"] != "+79281234567" || event["time_utc"] == "" {
		t.Fatalf("unexpected event: %s", contents)
	}
}

func TestDailyApprovalLogDateAndCutoff(t *testing.T) {
	date, ok := dailyApprovalLogDate("approval-2025-09-05.jsonl")
	if !ok || date.Format("2006-01-02") != "2025-09-05" {
		t.Fatalf("date=%v ok=%v", date, ok)
	}
	if _, ok := dailyApprovalLogDate("approval-2025-09.jsonl"); ok {
		t.Fatal("monthly legacy log must not be retained as a daily log")
	}
	cutoff := dailyLogCutoff(time.Date(2026, time.September, 5, 18, 0, 0, 0, time.UTC), 365)
	if got := cutoff.Format("2006-01-02"); got != "2025-09-05" {
		t.Fatalf("cutoff=%s", got)
	}
}

func TestReadApprovalLogsKeepsLegacyMonthlyLog(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"approval-2026-09.jsonl", "approval-2026-09-05.jsonl", "other.jsonl"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a := &app{cfg: config{LogPath: filepath.Join(dir, "approval.log")}}
	logs, err := a.readApprovalLogs()
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 || logs[0].name != "approval-2026-09-05.jsonl" || logs[1].name != "approval-2026-09.jsonl" {
		t.Fatalf("logs=%+v", logs)
	}
}

func TestLocalAuthQuotaAndQueueBytes(t *testing.T) {
	queue := map[string]any{
		"comment": "local-auth expires=1788600928 quota=150000000 mac=AA:BB:CC:DD:EE:FF",
		"bytes":   "120000000/30000000",
	}
	quota, ok := localAuthQuota(queue)
	if !ok || quota != 150000000 {
		t.Fatalf("quota=%d ok=%v", quota, ok)
	}
	used, ok := queueByteTotal(queue["bytes"])
	if !ok || used != 150000000 {
		t.Fatalf("used=%d ok=%v", used, ok)
	}
	if mac := queueMAC("local-auth-aabbccddeeff"); mac != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("mac=%q", mac)
	}
}

func TestQueueByteTotalRejectsMalformedCounter(t *testing.T) {
	for _, value := range []any{"100", "100/not-a-number", 100} {
		if _, ok := queueByteTotal(value); ok {
			t.Fatalf("queue bytes %v were accepted", value)
		}
	}
}

func TestCleanupQuotaGrantsRevokesEveryPermission(t *testing.T) {
	comment := "local-auth expires=1788600928 quota=150000000"
	deleted := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted[r.URL.Path] = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/rest/queue/simple":
			_, _ = io.WriteString(w, `[{".id":"*1","name":"local-auth-aabbccddeeff","comment":"`+comment+`","bytes":"149000000/1000000"}]`)
		case "/rest/ip/hotspot/ip-binding":
			_, _ = io.WriteString(w, `[{".id":"*2","mac-address":"AA:BB:CC:DD:EE:FF","comment":"`+comment+`"}]`)
		case "/rest/ip/firewall/address-list":
			_, _ = io.WriteString(w, `[{".id":"*3","comment":"`+comment+` mac=AA:BB:CC:DD:EE:FF"}]`)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	a := &app{cfg: config{GaragePassword: "secret", LogPath: filepath.Join(t.TempDir(), "approval.log")}, router: client{base: server.URL, http: server.Client()}}
	if err := a.cleanupQuotaGrants(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/rest/queue/simple/*1", "/rest/ip/hotspot/ip-binding/*2", "/rest/ip/firewall/address-list/*3"} {
		if !deleted[path] {
			t.Fatalf("not deleted: %s", path)
		}
	}
}
