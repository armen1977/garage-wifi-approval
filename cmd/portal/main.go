package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type config struct {
	ListenAddr, GarageURL, GarageUser, GaragePassword, HotspotServer, GuestRateLimit string
	GrantMinutes                                                                     int
	GuestDataLimitBytes                                                              int64
	RequestTTL                                                                       time.Duration
	AdminUser, AdminPassword, LogPath                                                string
	BackupFTPURL, BackupFTPUser, BackupFTPPass, BackupRemoteDir                      string
	LogRetentionDays                                                                 int
	AdminCIDRs                                                                       []*net.IPNet
	HiLinkURL, SMSPrefix                                                             string
	SMSCodeTTL, SMSRetryDelay                                                        time.Duration
	SMSMaxPerHour, SMSGlobalMaxPerHour                                               int
}

type backupStatus struct {
	Configured     bool   `json:"configured"`
	RetentionDays  int    `json:"retention_days"`
	LastAttemptUTC string `json:"last_attempt_utc,omitempty"`
	LastSuccessUTC string `json:"last_success_utc,omitempty"`
	LastUploaded   int    `json:"last_uploaded_files,omitempty"`
	LastPruned     int    `json:"last_pruned_files,omitempty"`
	LastError      string `json:"last_error,omitempty"`
}

type request struct {
	ID, ClientIP, MAC        string
	CreatedAt, ExpiresAt     time.Time
	ApprovedAt, GrantedUntil time.Time
}

type smsCode struct {
	Phone, ClientIP, MAC, Value string
	ExpiresAt, SentAt           time.Time
	Attempts, Resends           int
	Sending                     bool
}

type rateWindow struct {
	StartedAt time.Time
	Count     int
}

type app struct {
	cfg            config
	router         client
	hiLink         hiLinkClient
	mu             sync.Mutex
	pending        map[string]request
	codes          map[string]smsCode
	smsRateLimits  map[string]rateWindow
	globalSMSLimit rateWindow
	logMu          sync.Mutex
	backupMu       sync.RWMutex
	backup         backupStatus
}

type client struct {
	base, user, pass string
	http             *http.Client
}

type hiLinkClient struct {
	base string
	http *http.Client
}

type hiLinkSession struct {
	Session string `xml:"SesInfo"`
	Token   string `xml:"TokInfo"`
}

type hiLinkSMSRequest struct {
	XMLName  xml.Name `xml:"request"`
	Index    int      `xml:"Index"`
	Phones   []string `xml:"Phones>Phone"`
	Sca      string   `xml:"Sca"`
	Content  string   `xml:"Content"`
	Length   int      `xml:"Length"`
	Reserved int      `xml:"Reserved"`
	Date     string   `xml:"Date"`
}

type hiLinkSMSResponse struct {
	Value string `xml:",chardata"`
	Code  string `xml:"code"`
}

var (
	macRE          = regexp.MustCompile(`^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$`)
	smsCodeRE      = regexp.MustCompile(`^[0-9]{6}$`)
	moscowLocation = time.FixedZone("Europe/Moscow", 3*60*60)
)

const approvedGuestAddressList = "garage-guest-approved"

func main() {
	a := newApp()
	go a.cleanup()
	go a.backupLoop()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.health)
	mux.HandleFunc("/backup/status", a.backupStatus)
	mux.HandleFunc("/", a.home)
	mux.HandleFunc("/request", a.request)
	mux.HandleFunc("/status", a.status)
	mux.HandleFunc("/admin", a.admin)
	mux.HandleFunc("/approve", a.approve)
	mux.HandleFunc("/sms", a.sms)
	mux.HandleFunc("/sms/start", a.smsStart)
	mux.HandleFunc("/sms/resend", a.smsResend)
	mux.HandleFunc("/sms/verify", a.smsVerify)
	log.Fatal(http.ListenAndServe(a.cfg.ListenAddr, mux))
}

func newApp() *app {
	cfg := config{
		ListenAddr: env("LISTEN_ADDR", ":8080"), GarageURL: strings.TrimRight(env("GARAGE_ROUTER_URL", "http://192.168.50.1"), "/"),
		GarageUser: env("GARAGE_ROUTER_USER", "approval-api"), GaragePassword: env("GARAGE_ROUTER_PASSWORD", ""),
		HotspotServer: env("HOTSPOT_SERVER", "hotspot-guest"), GuestRateLimit: env("GUEST_RATE_LIMIT", "5M/20M"),
		GrantMinutes: num("GRANT_MINUTES", 60), GuestDataLimitBytes: num64("GUEST_DATA_LIMIT_BYTES", 0),
		RequestTTL: time.Duration(num("REQUEST_TTL_SECONDS", 600)) * time.Second,
		AdminUser:  env("ADMIN_USER", "master"), AdminPassword: env("ADMIN_PASSWORD", ""), AdminCIDRs: adminCIDRs(env("ADMIN_CIDRS", env("ADMIN_CIDR", "192.168.50.0/24"))),
		LogPath:      env("LOG_PATH", "/data/approval.log"),
		BackupFTPURL: strings.TrimRight(env("BACKUP_FTP_URL", ""), "/"), BackupFTPUser: env("BACKUP_FTP_USER", "anonymous"),
		BackupFTPPass: env("BACKUP_FTP_PASSWORD", "anonymous"), BackupRemoteDir: env("BACKUP_REMOTE_DIR", "Garage-WiFi-Logs"),
		LogRetentionDays:    num("LOG_RETENTION_DAYS", 365),
		HiLinkURL:           strings.TrimRight(env("HILINK_URL", ""), "/"),
		SMSPrefix:           env("SMS_MESSAGE_PREFIX", "Garage Wi-Fi code: "),
		SMSCodeTTL:          time.Duration(num("SMS_CODE_TTL_SECONDS", 300)) * time.Second,
		SMSRetryDelay:       time.Duration(num("SMS_RETRY_DELAY_SECONDS", 120)) * time.Second,
		SMSMaxPerHour:       num("SMS_MAX_PER_HOUR", 2),
		SMSGlobalMaxPerHour: num("SMS_GLOBAL_MAX_PER_HOUR", 20),
	}
	return &app{
		cfg:           cfg,
		router:        client{base: cfg.GarageURL, user: cfg.GarageUser, pass: cfg.GaragePassword, http: &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}},
		hiLink:        hiLinkClient{base: cfg.HiLinkURL, http: &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}},
		pending:       map[string]request{},
		codes:         map[string]smsCode{},
		smsRateLimits: map[string]rateWindow{},
		backup:        backupStatus{Configured: cfg.BackupFTPURL != "", RetentionDays: cfg.LogRetentionDays},
	}
}

func adminCIDRs(value string) []*net.IPNet {
	var cidrs []*net.IPNet
	for _, raw := range strings.Split(value, ",") {
		_, cidr, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err == nil {
			cidrs = append(cidrs, cidr)
		}
	}
	if len(cidrs) != 0 {
		return cidrs
	}
	_, fallback, _ := net.ParseCIDR("192.168.50.0/24")
	return []*net.IPNet{fallback}
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func num(key string, fallback int) int {
	value, err := strconv.Atoi(env(key, ""))
	if err != nil || value < 1 {
		return fallback
	}
	return value
}

func num64(key string, fallback int64) int64 {
	value, err := strconv.ParseInt(env(key, ""), 10, 64)
	if err != nil || value < 0 {
		return fallback
	}
	return value
}

func (a *app) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("OK"))
}

func (a *app) backupStatus(w http.ResponseWriter, _ *http.Request) {
	a.backupMu.RLock()
	status := a.backup
	a.backupMu.RUnlock()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(status)
}

func (a *app) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	ip, mac := formContext(r)
	a.page(w, "Гостевой Wi-Fi", fmt.Sprintf(`<h1>Гостевой Wi-Fi</h1><p>Выберите способ входа.</p>%s<div class="actions"><form method="post" action="/request"><input type="hidden" name="client_ip" value="%s"><input type="hidden" name="mac" value="%s"><button>Запросить доступ у мастера</button></form><form method="get" action="/sms"><input type="hidden" name="client_ip" value="%s"><input type="hidden" name="mac" value="%s"><button>Войти по SMS-коду</button></form></div>`, privacyNotice(), html.EscapeString(ip), html.EscapeString(mac), html.EscapeString(ip), html.EscapeString(mac)))
}

func (a *app) sms(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if a.cfg.HiLinkURL == "" {
		a.errorPage(w, "SMS-вход временно недоступен.")
		return
	}
	ip, mac := formContext(r)
	if !validIP(ip) || !macRE.MatchString(mac) {
		a.errorPage(w, "Не удалось определить устройство. Подключитесь к Garage-Guest заново.")
		return
	}
	a.page(w, "SMS-код", fmt.Sprintf(`<h1>Вход по SMS-коду</h1><p>Введите номер телефона.</p>%s<form method="post" action="/sms/start" onsubmit="var b=this.querySelector('button');b.disabled=true;b.textContent='Отправляем...' "><input type="hidden" name="client_ip" value="%s"><input type="hidden" name="mac" value="%s"><label class="phone"><span>+7</span><input name="phone" type="tel" inputmode="tel" autocomplete="tel-national" placeholder="928 123-45-67" required></label><button>Получить SMS-код</button></form><p><a href="/?client_ip=%s&mac=%s">Запросить доступ у мастера</a></p>`, privacyNotice(), html.EscapeString(ip), html.EscapeString(mac), url.QueryEscape(ip), url.QueryEscape(mac)))
}

func privacyNotice() string {
	return `<p class="notice">Для подтверждения доступа сохраняются время, IP-адрес, MAC-адрес и способ входа. При входе по SMS сохраняется подтверждённый номер телефона. Срок хранения записей - 365 дней.</p>`
}

func (a *app) smsStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	ip, mac := formContext(r)
	phone := normalizePhone(r.FormValue("phone"))
	if !validIP(ip) || !macRE.MatchString(mac) {
		a.errorPage(w, "Не удалось определить устройство. Подключитесь к Garage-Guest заново.")
		return
	}
	if phone == "" {
		a.errorPage(w, "Введите корректный номер телефона.")
		return
	}
	req := request{ClientIP: ip, MAC: mac}
	active, err := a.bindingActive(req)
	if err != nil {
		a.errorPage(w, "Состояние доступа временно не удалось проверить. Попробуйте ещё раз.")
		return
	}
	if active {
		a.page(w, "Доступ уже открыт", "<h1>Доступ уже открыт</h1><p>Повторный SMS-код не нужен.</p>")
		return
	}
	state, err := a.createOrResendSMSCode(req, phone)
	if err != nil {
		a.errorPage(w, err.Error())
		return
	}
	a.renderSMSVerify(w, req, phone, state)
}

func (a *app) smsResend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	ip, mac := formContext(r)
	if !validIP(ip) || !macRE.MatchString(mac) {
		a.errorPage(w, "Не удалось определить устройство. Подключитесь к Garage-Guest заново.")
		return
	}
	req := request{ClientIP: ip, MAC: mac}
	a.mu.Lock()
	state, ok := a.codes[smsKey(req)]
	a.mu.Unlock()
	if !ok || time.Now().After(state.ExpiresAt) {
		a.errorPage(w, "SMS-код не найден или истёк. Получите новый код.")
		return
	}
	state, err := a.createOrResendSMSCode(req, state.Phone)
	if err != nil {
		a.errorPage(w, err.Error())
		return
	}
	a.renderSMSVerify(w, req, state.Phone, state)
}

func (a *app) smsVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	ip, mac := formContext(r)
	code := strings.TrimSpace(r.FormValue("code"))
	if !validIP(ip) || !macRE.MatchString(mac) {
		a.errorPage(w, "Не удалось определить устройство. Подключитесь к Garage-Guest заново.")
		return
	}
	if !smsCodeRE.MatchString(code) {
		a.errorPage(w, "Введите шесть цифр из SMS.")
		return
	}
	req := request{ClientIP: ip, MAC: mac}
	key := smsKey(req)
	now := time.Now()
	a.mu.Lock()
	state, ok := a.codes[key]
	if !ok || state.Sending || now.After(state.ExpiresAt) || state.ClientIP != ip || !strings.EqualFold(state.MAC, mac) {
		if ok && now.After(state.ExpiresAt) {
			delete(a.codes, key)
		}
		a.mu.Unlock()
		a.errorPage(w, "SMS-код не найден или истёк. Получите новый код.")
		return
	}
	if subtle.ConstantTimeCompare([]byte(code), []byte(state.Value)) != 1 {
		state.Attempts++
		if state.Attempts >= 5 {
			delete(a.codes, key)
		} else {
			a.codes[key] = state
		}
		a.mu.Unlock()
		a.logEvent(map[string]any{"type": "sms_bad_code", "client_ip": ip, "mac": mac})
		if state.Attempts >= 5 {
			a.errorPage(w, "Слишком много неверных попыток. Получите новый код.")
			return
		}
		a.renderSMSVerify(w, req, state.Phone, state)
		return
	}
	state.Sending = true
	a.codes[key] = state
	a.mu.Unlock()

	until, err := a.grant(req)
	if err != nil {
		a.mu.Lock()
		if current, found := a.codes[key]; found {
			current.Sending = false
			a.codes[key] = current
		}
		a.mu.Unlock()
		a.logEvent(map[string]any{"type": "sms_grant_error", "client_ip": ip, "mac": mac, "error": err.Error()})
		a.errorPage(w, "Доступ выдать не удалось. Повторите ввод кода через несколько секунд.")
		return
	}
	go a.expireGrant(req, until)
	a.mu.Lock()
	delete(a.codes, key)
	a.removePendingFor(req)
	a.mu.Unlock()
	// A number is recorded only after its one-time code was accepted.
	a.logEvent(map[string]any{"type": "access_granted", "method": "sms", "client_ip": ip, "mac": mac, "phone_e164": state.Phone, "expires_utc": until.Format(time.RFC3339), "expires_unix": until.Unix()})
	a.page(w, "Готово", fmt.Sprintf("<h1>Готово</h1><p>SMS-код принят. Доступ открыт на %d минут.</p>", a.cfg.GrantMinutes))
}

func (a *app) renderSMSVerify(w http.ResponseWriter, req request, phone string, state smsCode) {
	masked := maskPhone(phone)
	remaining := int(time.Until(state.ExpiresAt).Round(time.Second).Seconds())
	if remaining < 1 {
		remaining = 1
	}
	a.page(w, "SMS-код", fmt.Sprintf(`<h1>Код из SMS</h1><p>Код отправлен на %s. Он действует %d секунд.</p><form method="post" action="/sms/verify" onsubmit="var b=this.querySelector('button');b.disabled=true;b.textContent='Проверяем...' "><input type="hidden" name="client_ip" value="%s"><input type="hidden" name="mac" value="%s"><input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="Шесть цифр" required autofocus><button>Подтвердить код</button></form><form method="post" action="/sms/resend" onsubmit="var b=this.querySelector('button');b.disabled=true;b.textContent='Отправляем...' "><input type="hidden" name="client_ip" value="%s"><input type="hidden" name="mac" value="%s"><button>Отправить код повторно</button></form>`, html.EscapeString(masked), remaining, html.EscapeString(req.ClientIP), html.EscapeString(req.MAC), html.EscapeString(req.ClientIP), html.EscapeString(req.MAC)))
}

func (a *app) request(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	ip, mac := formContext(r)
	if !validIP(ip) {
		a.errorPage(w, "Не удалось определить устройство.")
		return
	}

	now := time.Now()
	a.mu.Lock()
	for _, existing := range a.pending {
		if existing.ClientIP != ip || existing.MAC != mac {
			continue
		}
		if !existing.ApprovedAt.IsZero() && now.Before(existing.GrantedUntil) {
			a.mu.Unlock()
			http.Redirect(w, r, "/status?id="+url.QueryEscape(existing.ID), http.StatusSeeOther)
			return
		}
		if existing.ApprovedAt.IsZero() && now.Before(existing.ExpiresAt) {
			a.mu.Unlock()
			http.Redirect(w, r, "/status?id="+url.QueryEscape(existing.ID), http.StatusSeeOther)
			return
		}
	}
	id, err := randomID()
	if err == nil {
		a.pending[id] = request{ID: id, ClientIP: ip, MAC: mac, CreatedAt: now.UTC(), ExpiresAt: now.Add(a.cfg.RequestTTL).UTC()}
	}
	a.mu.Unlock()
	if err != nil {
		a.errorPage(w, "Не удалось создать заявку.")
		return
	}
	a.logEvent(map[string]any{"type": "request_created", "request_id": id, "client_ip": ip, "mac": mac})
	http.Redirect(w, r, "/status?id="+url.QueryEscape(id), http.StatusSeeOther)
}

// createRequest is kept for the focused request-creation test.
func (a *app) createRequest(w http.ResponseWriter, r *http.Request) {
	a.request(w, r)
}

func (a *app) status(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	a.mu.Lock()
	req, ok := a.pending[id]
	a.mu.Unlock()
	if !ok {
		a.errorPage(w, "Заявка не найдена или устарела.")
		return
	}

	if !req.ApprovedAt.IsZero() {
		active, err := a.bindingActive(req)
		if err != nil {
			a.errorPage(w, "Подтверждение получено, но состояние доступа временно не удалось проверить. Попробуйте обновить страницу.")
			return
		}
		if active {
			a.page(w, "Доступ открыт", fmt.Sprintf(`<h1>Доступ открыт</h1><p>Мастер подтвердил заявку. Доступ действует до %s.</p>`, displayMoscowTime(req.GrantedUntil)))
			return
		}
		a.page(w, "Доступ завершён", `<h1>Доступ завершён</h1><p>Время доступа истекло. Отправьте новую заявку мастеру.</p>`)
		return
	}
	if time.Now().After(req.ExpiresAt) {
		a.errorPage(w, "Заявка не найдена или устарела.")
		return
	}
	body := fmt.Sprintf(`<h1>Заявка принята</h1><p>Покажите мастеру номер: <strong>%s</strong>.</p><p>Страница обновляется автоматически.</p><script>setTimeout(()=>location.reload(),5000)</script>`, html.EscapeString(id))
	a.page(w, "Ожидание", body)
}

func (a *app) admin(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeAdmin(w, r) {
		return
	}
	now := time.Now()
	a.mu.Lock()
	items := make([]request, 0, len(a.pending))
	for _, req := range a.pending {
		if req.ApprovedAt.IsZero() && now.Before(req.ExpiresAt) {
			items = append(items, req)
		}
	}
	a.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
	var body strings.Builder
	body.WriteString("<h1>Заявки на Wi-Fi</h1>")
	if len(items) == 0 {
		body.WriteString("<p>Активных заявок нет.</p>")
	}
	for _, req := range items {
		fmt.Fprintf(&body, `<section><strong>%s</strong><br>Устройство: %s / %s<form method="post" action="/approve"><input type="hidden" name="id" value="%s"><input name="order_ref" maxlength="64" placeholder="Номер заказа или госномер" required><button>Подтвердить доступ</button></form></section>`, html.EscapeString(req.ID), html.EscapeString(req.ClientIP), html.EscapeString(req.MAC), html.EscapeString(req.ID))
	}
	a.page(w, "Подтверждение Wi-Fi", body.String())
}

func (a *app) approve(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	id := strings.TrimSpace(r.FormValue("id"))
	orderRef := strings.TrimSpace(r.FormValue("order_ref"))
	if orderRef == "" || len(orderRef) > 64 {
		a.errorPage(w, "Укажите номер заказа или госномер.")
		return
	}

	a.mu.Lock()
	req, ok := a.pending[id]
	a.mu.Unlock()
	if !ok || !req.ApprovedAt.IsZero() || time.Now().After(req.ExpiresAt) {
		a.errorPage(w, "Заявка устарела.")
		return
	}

	until, err := a.grant(req)
	if err != nil {
		a.logEvent(map[string]any{"type": "grant_error", "request_id": id, "client_ip": req.ClientIP, "mac": req.MAC, "order_ref": orderRef, "error": err.Error()})
		a.errorPage(w, "Доступ выдать не удалось. SMS-доступ не изменён.")
		return
	}
	// RouterOS address-list timeout is the fail-closed expiry boundary. The
	// goroutine removes the remaining state promptly; a router restart cannot
	// leave the firewall permission active beyond the approved interval.
	go a.expireGrant(req, until)

	a.mu.Lock()
	req.ApprovedAt = time.Now().UTC()
	req.GrantedUntil = until
	a.pending[id] = req
	delete(a.codes, smsKey(req))
	a.mu.Unlock()
	operator, _, _ := r.BasicAuth()
	a.logEvent(map[string]any{"type": "access_granted", "request_id": id, "client_ip": req.ClientIP, "mac": req.MAC, "order_ref": orderRef, "operator": operator, "expires_utc": until.Format(time.RFC3339), "expires_unix": until.Unix()})
	a.page(w, "Готово", fmt.Sprintf("<h1>Готово</h1><p>Доступ открыт на %d минут.</p>", a.cfg.GrantMinutes))
}

func (a *app) grant(req request) (time.Time, error) {
	if a.cfg.GaragePassword == "" {
		return time.Time{}, errors.New("GARAGE_ROUTER_PASSWORD is empty")
	}
	if !macRE.MatchString(req.MAC) {
		return time.Time{}, errors.New("device MAC is required")
	}
	if err := a.validateHotspotHost(req); err != nil {
		return time.Time{}, err
	}
	if err := a.revokeLocalAuth(req.MAC); err != nil {
		return time.Time{}, err
	}
	until := time.Now().Add(time.Duration(a.cfg.GrantMinutes) * time.Minute).UTC()
	comment := fmt.Sprintf("local-auth expires=%d", until.Unix())
	if a.cfg.GuestDataLimitBytes > 0 {
		comment += fmt.Sprintf(" quota=%d", a.cfg.GuestDataLimitBytes)
	}
	name := "local-auth-" + strings.ReplaceAll(strings.ToLower(req.MAC), ":", "")
	queue := map[string]string{"name": name, "target": req.ClientIP + "/32", "max-limit": a.cfg.GuestRateLimit, "comment": comment + " mac=" + req.MAC}
	if err := a.router.put("/queue/simple", queue); err != nil {
		return time.Time{}, err
	}
	binding := map[string]string{"server": a.cfg.HotspotServer, "address": req.ClientIP, "mac-address": req.MAC, "type": "bypassed", "comment": comment}
	if err := a.router.put("/ip/hotspot/ip-binding", binding); err != nil {
		_ = a.revokeLocalAuth(req.MAC)
		return time.Time{}, err
	}
	if err := a.addApprovedGuest(req, until, comment); err != nil {
		_ = a.revokeLocalAuth(req.MAC)
		return time.Time{}, err
	}
	return until, nil
}

func (a *app) addApprovedGuest(req request, until time.Time, comment string) error {
	remaining := time.Until(until).Round(time.Second)
	if remaining <= 0 {
		return errors.New("grant has already expired")
	}
	entry := map[string]string{
		"list":    approvedGuestAddressList,
		"address": req.ClientIP,
		"timeout": fmt.Sprintf("%ds", int64(remaining.Seconds())),
		"comment": comment + " mac=" + req.MAC,
	}
	return a.router.put("/ip/firewall/address-list", entry)
}

func (a *app) validateHotspotHost(req request) error {
	var hosts []map[string]any
	if err := a.router.get("/ip/hotspot/host", &hosts); err != nil {
		return fmt.Errorf("list hotspot hosts: %w", err)
	}
	for _, host := range hosts {
		address, _ := host["address"].(string)
		if address != req.ClientIP {
			continue
		}
		macRaw, _ := host["mac-address"].(string)
		mac := normalizeMAC(macRaw)
		if mac == "" {
			return errors.New("hotspot host MAC is missing")
		}
		if !strings.EqualFold(mac, req.MAC) {
			return errors.New("hotspot host does not match request")
		}
		return nil
	}
	return errors.New("hotspot host is not active")
}

func (a *app) bindingActive(req request) (bool, error) {
	var items []map[string]any
	if err := a.router.get("/ip/hotspot/ip-binding", &items); err != nil {
		return false, err
	}
	for _, item := range items {
		mac, _ := item["mac-address"].(string)
		address, _ := item["address"].(string)
		comment, _ := item["comment"].(string)
		kind, _ := item["type"].(string)
		if strings.EqualFold(mac, req.MAC) && address == req.ClientIP && kind == "bypassed" && strings.HasPrefix(comment, "local-auth expires=") {
			return true, nil
		}
	}
	return false, nil
}

func (a *app) createOrResendSMSCode(req request, phone string) (smsCode, error) {
	if a.cfg.HiLinkURL == "" {
		return smsCode{}, errors.New("SMS-вход временно недоступен")
	}
	now := time.Now()
	key := smsKey(req)

	a.mu.Lock()
	state, exists := a.codes[key]
	if exists && now.After(state.ExpiresAt) {
		delete(a.codes, key)
		exists = false
	}
	if exists {
		if state.Sending {
			a.mu.Unlock()
			return smsCode{}, errors.New("SMS-код уже отправляется. Подождите несколько секунд")
		}
		if state.Phone != phone {
			a.mu.Unlock()
			return smsCode{}, errors.New("Для этого устройства уже отправлен SMS-код. Используйте его или дождитесь окончания срока")
		}
		if now.Sub(state.SentAt) < a.cfg.SMSRetryDelay {
			wait := int((a.cfg.SMSRetryDelay - now.Sub(state.SentAt)).Round(time.Second).Seconds())
			a.mu.Unlock()
			return smsCode{}, fmt.Errorf("повторную отправку можно запросить через %d секунд", wait)
		}
		if state.Resends >= 1 {
			a.mu.Unlock()
			return smsCode{}, errors.New("повторная отправка уже использована. Получите новый код после окончания срока")
		}
		if !a.reserveSMSLocked(req, phone, now) {
			a.mu.Unlock()
			return smsCode{}, errors.New("лимит SMS для устройства или номера исчерпан. Попробуйте позже")
		}
		state.Sending = true
		a.codes[key] = state
		a.mu.Unlock()

		if err := a.sendSMS(phone, state.Value); err != nil {
			a.mu.Lock()
			state.Sending = false
			a.codes[key] = state
			a.releaseSMSLocked(req, phone)
			a.mu.Unlock()
			a.logEvent(map[string]any{"type": "sms_error", "client_ip": req.ClientIP, "mac": req.MAC, "error": err.Error()})
			return smsCode{}, errors.New("SMS отправить не удалось. Попробуйте ещё раз")
		}
		now = time.Now()
		a.mu.Lock()
		state.Sending = false
		state.SentAt = now
		state.Resends++
		a.codes[key] = state
		a.mu.Unlock()
		a.logEvent(map[string]any{"type": "sms_resent", "client_ip": req.ClientIP, "mac": req.MAC})
		return state, nil
	}

	code, err := randomSMSCode()
	if err != nil {
		a.mu.Unlock()
		return smsCode{}, errors.New("не удалось создать SMS-код")
	}
	if !a.reserveSMSLocked(req, phone, now) {
		a.mu.Unlock()
		return smsCode{}, errors.New("лимит SMS для устройства или номера исчерпан. Попробуйте позже")
	}
	state = smsCode{Phone: phone, ClientIP: req.ClientIP, MAC: req.MAC, Value: code, ExpiresAt: now.Add(a.cfg.SMSCodeTTL), Sending: true}
	a.codes[key] = state
	a.mu.Unlock()

	if err := a.sendSMS(phone, code); err != nil {
		a.mu.Lock()
		delete(a.codes, key)
		a.releaseSMSLocked(req, phone)
		a.mu.Unlock()
		a.logEvent(map[string]any{"type": "sms_error", "client_ip": req.ClientIP, "mac": req.MAC, "error": err.Error()})
		return smsCode{}, errors.New("SMS отправить не удалось. Попробуйте ещё раз")
	}

	now = time.Now()
	a.mu.Lock()
	state.Sending = false
	state.SentAt = now
	a.codes[key] = state
	a.mu.Unlock()
	a.logEvent(map[string]any{"type": "sms_sent", "client_ip": req.ClientIP, "mac": req.MAC})
	return state, nil
}

func (a *app) reserveSMSLocked(req request, phone string, now time.Time) bool {
	deviceKey := "device:" + strings.ToLower(req.MAC)
	phoneKey := "phone:" + phone
	if !rateAvailable(a.smsRateLimits[deviceKey], now, a.cfg.SMSMaxPerHour) || !rateAvailable(a.smsRateLimits[phoneKey], now, a.cfg.SMSMaxPerHour) || !rateAvailable(a.globalSMSLimit, now, a.cfg.SMSGlobalMaxPerHour) {
		return false
	}
	a.smsRateLimits[deviceKey] = incrementRate(a.smsRateLimits[deviceKey], now)
	a.smsRateLimits[phoneKey] = incrementRate(a.smsRateLimits[phoneKey], now)
	a.globalSMSLimit = incrementRate(a.globalSMSLimit, now)
	return true
}

func (a *app) releaseSMSLocked(req request, phone string) {
	for _, key := range []string{"device:" + strings.ToLower(req.MAC), "phone:" + phone} {
		window := a.smsRateLimits[key]
		if window.Count > 0 {
			window.Count--
			a.smsRateLimits[key] = window
		}
	}
	if a.globalSMSLimit.Count > 0 {
		a.globalSMSLimit.Count--
	}
}

func rateAvailable(window rateWindow, now time.Time, limit int) bool {
	if window.StartedAt.IsZero() || now.Sub(window.StartedAt) >= time.Hour {
		return true
	}
	return window.Count < limit
}

func incrementRate(window rateWindow, now time.Time) rateWindow {
	if window.StartedAt.IsZero() || now.Sub(window.StartedAt) >= time.Hour {
		return rateWindow{StartedAt: now, Count: 1}
	}
	window.Count++
	return window
}

func (a *app) sendSMS(phone, code string) error {
	if a.hiLink.base == "" {
		return errors.New("HILINK_URL is empty")
	}
	return a.hiLink.sendSMS(phone, a.cfg.SMSPrefix+code)
}

func (h hiLinkClient) sendSMS(phone, message string) error {
	session, err := h.session()
	if err != nil {
		return fmt.Errorf("HiLink session: %w", err)
	}
	payload, err := xml.Marshal(hiLinkSMSRequest{
		Index: -1, Phones: []string{phone}, Content: message, Length: utf8.RuneCountInString(message), Reserved: 1,
		Date: time.Now().In(moscowLocation).Format("2006-01-02 15:04:05"),
	})
	if err != nil {
		return err
	}
	httpRequest, err := http.NewRequest(http.MethodPost, h.base+"/api/sms/send-sms", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	httpRequest.Header.Set("X-Requested-With", "XMLHttpRequest")
	httpRequest.Header.Set("Cookie", session.Session)
	httpRequest.Header.Set("__RequestVerificationToken", session.Token)
	response, err := h.http.Do(httpRequest)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("HiLink SMS: %s", response.Status)
	}
	var result hiLinkSMSResponse
	if err := xml.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode HiLink SMS response: %w", err)
	}
	if strings.EqualFold(strings.TrimSpace(result.Value), "OK") {
		return nil
	}
	if result.Code != "" {
		return fmt.Errorf("HiLink SMS rejected with code %s", result.Code)
	}
	return errors.New("HiLink SMS returned an unexpected response")
}

func (h hiLinkClient) session() (hiLinkSession, error) {
	response, err := h.http.Get(h.base + "/api/webserver/SesTokInfo")
	if err != nil {
		return hiLinkSession{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return hiLinkSession{}, fmt.Errorf("%s", response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return hiLinkSession{}, err
	}
	var session hiLinkSession
	if err := xml.Unmarshal(data, &session); err != nil {
		return hiLinkSession{}, err
	}
	if session.Session == "" || session.Token == "" {
		return hiLinkSession{}, errors.New("session or verification token is missing")
	}
	return session, nil
}

func smsKey(req request) string {
	return req.ClientIP + "|" + strings.ToLower(req.MAC)
}

func (a *app) removePendingFor(target request) {
	for id, req := range a.pending {
		if req.ApprovedAt.IsZero() && req.ClientIP == target.ClientIP && strings.EqualFold(req.MAC, target.MAC) {
			delete(a.pending, id)
		}
	}
}

func (a *app) authorizeAdmin(w http.ResponseWriter, r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !a.adminIPAllowed(net.ParseIP(host)) {
		http.NotFound(w, r)
		return false
	}
	user, pass, ok := r.BasicAuth()
	if !ok || a.cfg.AdminPassword == "" || user != a.cfg.AdminUser || pass != a.cfg.AdminPassword {
		w.Header().Set("WWW-Authenticate", `Basic realm="Garage Wi-Fi"`)
		http.Error(w, "authorization required", http.StatusUnauthorized)
		return false
	}
	return true
}

func (a *app) adminIPAllowed(ip net.IP) bool {
	for _, cidr := range a.cfg.AdminCIDRs {
		if cidr != nil && cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *app) cleanup() {
	// Reconcile any access left behind by a container or router restart.
	if err := a.cleanupExpiredGrants(time.Now().UTC().Unix()); err != nil {
		log.Printf("startup local-auth cleanup: %v", err)
	}
	a.restoreActiveGrants()
	a.cleanupPending()
	expiryTicker := time.NewTicker(time.Minute)
	quotaTicker := time.NewTicker(5 * time.Second)
	defer expiryTicker.Stop()
	defer quotaTicker.Stop()
	for {
		select {
		case <-expiryTicker.C:
			a.cleanupPending()
			if err := a.cleanupExpiredGrants(time.Now().UTC().Unix()); err != nil {
				log.Printf("periodic local-auth cleanup: %v", err)
			}
		case <-quotaTicker.C:
			if err := a.cleanupQuotaGrants(); err != nil {
				log.Printf("local-auth quota check: %v", err)
			}
		}
	}
}

func (a *app) cleanupPending() {
	now := time.Now().UTC()
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, req := range a.pending {
		if req.ApprovedAt.IsZero() && now.After(req.ExpiresAt) {
			delete(a.pending, id)
			a.logEvent(map[string]any{"type": "request_expired", "request_id": id, "client_ip": req.ClientIP, "mac": req.MAC})
			continue
		}
		if !req.ApprovedAt.IsZero() && now.After(req.GrantedUntil.Add(10*time.Minute)) {
			delete(a.pending, id)
		}
	}
	for key, state := range a.codes {
		if now.After(state.ExpiresAt) {
			delete(a.codes, key)
		}
	}
}

func (a *app) backupLoop() {
	if a.cfg.BackupFTPURL == "" {
		return
	}
	a.attemptBackup()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		a.attemptBackup()
	}
}

func (a *app) attemptBackup() {
	a.backupMu.Lock()
	a.backup.LastAttemptUTC = time.Now().UTC().Format(time.RFC3339)
	a.backup.LastError = ""
	a.backupMu.Unlock()

	uploaded, pruned, err := a.backupApprovalLogs()
	a.backupMu.Lock()
	defer a.backupMu.Unlock()
	if err != nil {
		a.backup.LastError = err.Error()
		log.Printf("approval log backup: %v", err)
		return
	}
	a.backup.LastSuccessUTC = time.Now().UTC().Format(time.RFC3339)
	a.backup.LastUploaded = uploaded
	a.backup.LastPruned = pruned
}

var (
	dailyApprovalLogRE   = regexp.MustCompile(`^approval-(\d{4})-(\d{2})-(\d{2})\.jsonl$`)
	monthlyApprovalLogRE = regexp.MustCompile(`^approval-\d{4}-\d{2}\.jsonl$`)
)

type approvalLogFile struct {
	name     string
	contents []byte
}

func (a *app) backupApprovalLogs() (int, int, error) {
	logs, err := a.readApprovalLogs()
	if err != nil {
		return 0, 0, err
	}
	if len(logs) == 0 {
		return 0, 0, nil
	}
	conn, err := connectFTP(a.cfg.BackupFTPURL, a.cfg.BackupFTPUser, a.cfg.BackupFTPPass, a.cfg.BackupRemoteDir)
	if err != nil {
		return 0, 0, err
	}
	defer conn.quit()
	for _, item := range logs {
		if err := conn.upload(item.name, item.contents); err != nil {
			return 0, 0, fmt.Errorf("upload %s: %w", item.name, err)
		}
	}
	pruned, err := conn.pruneDailyLogs(time.Now().UTC(), a.cfg.LogRetentionDays)
	if err != nil {
		return 0, 0, err
	}
	if err := a.pruneLocalDailyLogs(time.Now().UTC()); err != nil {
		return 0, 0, err
	}
	return len(logs), pruned, nil
}

func (a *app) readApprovalLogs() ([]approvalLogFile, error) {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	dir := filepath.Dir(a.cfg.LogPath)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var logs []approvalLogFile
	for _, entry := range entries {
		if entry.IsDir() || (!dailyApprovalLogRE.MatchString(entry.Name()) && !monthlyApprovalLogRE.MatchString(entry.Name())) {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		logs = append(logs, approvalLogFile{name: entry.Name(), contents: contents})
	}
	sort.Slice(logs, func(i, j int) bool { return logs[i].name < logs[j].name })
	return logs, nil
}

func (a *app) pruneLocalDailyLogs(now time.Time) error {
	cutoff := dailyLogCutoff(now, a.cfg.LogRetentionDays)
	a.logMu.Lock()
	defer a.logMu.Unlock()
	dir := filepath.Dir(a.cfg.LogPath)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		date, ok := dailyApprovalLogDate(entry.Name())
		if !ok || !date.Before(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func dailyLogCutoff(now time.Time, retentionDays int) time.Time {
	if retentionDays < 1 {
		retentionDays = 365
	}
	return time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -retentionDays)
}

func dailyApprovalLogDate(name string) (time.Time, bool) {
	matches := dailyApprovalLogRE.FindStringSubmatch(name)
	if len(matches) != 4 {
		return time.Time{}, false
	}
	date, err := time.Parse("2006-01-02", strings.Join(matches[1:], "-"))
	return date, err == nil
}

type ftpConn struct {
	control *textproto.Conn
	host    string
}

func connectFTP(rawURL, username, password, remoteDir string) (*ftpConn, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "ftp" || parsed.Host == "" {
		return nil, errors.New("BACKUP_FTP_URL must be ftp://host[:port]")
	}
	host := parsed.Host
	if parsed.Port() == "" {
		host = net.JoinHostPort(parsed.Hostname(), "21")
	}
	raw, err := net.DialTimeout("tcp", host, 20*time.Second)
	if err != nil {
		return nil, err
	}
	conn := &ftpConn{control: textproto.NewConn(raw), host: host}
	if _, _, err := conn.control.ReadResponse(220); err != nil {
		raw.Close()
		return nil, err
	}
	if err := conn.control.PrintfLine("USER %s", username); err != nil {
		raw.Close()
		return nil, err
	}
	if _, _, err := conn.control.ReadResponse(230); err != nil {
		responseErr, ok := err.(*textproto.Error)
		if !ok || responseErr.Code != 331 {
			raw.Close()
			return nil, err
		}
		if _, err := conn.command([]int{230}, "PASS %s", password); err != nil {
			raw.Close()
			return nil, err
		}
	}
	if _, err := conn.command([]int{200}, "TYPE I"); err != nil {
		raw.Close()
		return nil, err
	}
	dir := pathpkg.Base(strings.Trim(strings.TrimSpace(remoteDir), "/"))
	if dir == "" || dir == "." || dir == "/" {
		dir = "Garage-WiFi-Logs"
	}
	if _, err := conn.command([]int{250}, "CWD %s", dir); err != nil {
		if _, err := conn.command([]int{257, 250}, "MKD %s", dir); err != nil {
			_ = conn.quit()
			return nil, err
		}
		if _, err := conn.command([]int{250}, "CWD %s", dir); err != nil {
			_ = conn.quit()
			return nil, err
		}
	}
	return conn, nil
}

func (c *ftpConn) command(expect []int, format string, args ...any) (string, error) {
	if err := c.control.PrintfLine(format, args...); err != nil {
		return "", err
	}
	_, message, err := c.control.ReadResponse(expect[0])
	if err == nil {
		return message, nil
	}
	responseErr, ok := err.(*textproto.Error)
	if !ok {
		return "", err
	}
	for _, code := range expect[1:] {
		if responseErr.Code == code {
			return responseErr.Msg, nil
		}
	}
	return "", err
}

func (c *ftpConn) upload(name string, contents []byte) error {
	data, err := c.passiveDataConnection()
	if err != nil {
		return err
	}
	if _, err := c.command([]int{125, 150}, "STOR %s", name); err != nil {
		data.Close()
		return err
	}
	if _, err := data.Write(contents); err != nil {
		data.Close()
		return err
	}
	if err := data.Close(); err != nil {
		return err
	}
	_, err = c.readResponse([]int{226, 250})
	return err
}

func (c *ftpConn) passiveDataConnection() (net.Conn, error) {
	response, err := c.command([]int{229}, "EPSV")
	if err != nil {
		return nil, err
	}
	match := regexp.MustCompile(`\(\|\|\|([0-9]+)\|\)`).FindStringSubmatch(response)
	if len(match) != 2 {
		return nil, fmt.Errorf("invalid EPSV response %q", response)
	}
	host, _, err := net.SplitHostPort(c.host)
	if err != nil {
		return nil, err
	}
	return net.DialTimeout("tcp", net.JoinHostPort(host, match[1]), 20*time.Second)
}

func (c *ftpConn) listNames() ([]string, error) {
	data, err := c.passiveDataConnection()
	if err != nil {
		return nil, err
	}
	if _, err := c.command([]int{125, 150}, "NLST"); err != nil {
		data.Close()
		return nil, err
	}
	contents, readErr := io.ReadAll(data)
	closeErr := data.Close()
	_, responseErr := c.readResponse([]int{226, 250})
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if responseErr != nil {
		return nil, responseErr
	}
	return strings.Fields(string(contents)), nil
}

func (c *ftpConn) pruneDailyLogs(now time.Time, retentionDays int) (int, error) {
	names, err := c.listNames()
	if err != nil {
		return 0, fmt.Errorf("list remote archive: %w", err)
	}
	cutoff := dailyLogCutoff(now, retentionDays)
	removed := 0
	for _, name := range names {
		date, ok := dailyApprovalLogDate(pathpkg.Base(name))
		if !ok || !date.Before(cutoff) {
			continue
		}
		if _, err := c.command([]int{250}, "DELE %s", pathpkg.Base(name)); err != nil {
			return removed, fmt.Errorf("remove expired remote log %s: %w", name, err)
		}
		removed++
	}
	return removed, nil
}

func (c *ftpConn) readResponse(expect []int) (string, error) {
	_, message, err := c.control.ReadResponse(expect[0])
	if err == nil {
		return message, nil
	}
	responseErr, ok := err.(*textproto.Error)
	if !ok {
		return "", err
	}
	for _, code := range expect[1:] {
		if responseErr.Code == code {
			return responseErr.Msg, nil
		}
	}
	return "", err
}

func (c *ftpConn) quit() error {
	_, err := c.command([]int{221}, "QUIT")
	closeErr := c.control.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func (a *app) cleanupExpiredGrants(now int64) error {
	if a.cfg.GaragePassword == "" {
		return nil
	}
	var firstErr error
	for _, target := range []struct {
		path       string
		logRemoval bool
	}{
		{path: "/queue/simple"},
		{path: "/ip/hotspot/ip-binding", logRemoval: true},
		{path: "/ip/firewall/address-list"},
	} {
		var items []map[string]any
		if err := a.router.get(target.path, &items); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("list %s: %w", target.path, err)
			}
			continue
		}
		for _, item := range items {
			until, ok := localAuthExpiry(item)
			if !ok || until > now {
				continue
			}
			id, ok := item[".id"].(string)
			if !ok || id == "" {
				continue
			}
			if err := a.router.delete(target.path + "/" + id); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("delete %s: %w", target.path, err)
				}
				continue
			}
			if target.logRemoval {
				a.logEvent(map[string]any{"type": "access_expired", "client_ip": item["address"], "mac": item["mac-address"], "expires_unix": until})
			}
		}
	}
	return firstErr
}

func (a *app) cleanupQuotaGrants() error {
	if a.cfg.GaragePassword == "" {
		return nil
	}
	var queues []map[string]any
	if err := a.router.get("/queue/simple", &queues); err != nil {
		return fmt.Errorf("list simple queues: %w", err)
	}
	for _, queue := range queues {
		name, _ := queue["name"].(string)
		quota, ok := localAuthQuota(queue)
		if !strings.HasPrefix(name, "local-auth-") || !ok || quota == 0 {
			continue
		}
		used, ok := queueByteTotal(queue["bytes"])
		if !ok || used < quota {
			continue
		}
		until, ok := localAuthExpiry(queue)
		if !ok {
			continue
		}
		mac := queueMAC(name)
		if mac == "" {
			continue
		}
		if err := a.revokeGrantAt(mac, until); err != nil {
			return fmt.Errorf("revoke quota-exhausted grant for %s: %w", mac, err)
		}
		a.logEvent(map[string]any{"type": "access_quota_reached", "mac": mac, "bytes_used": used, "quota_bytes": quota, "expires_unix": until})
	}
	return nil
}

func (a *app) revokeLocalAuth(mac string) error {
	compactMAC := strings.ReplaceAll(strings.ToLower(mac), ":", "")
	var firstErr error
	for _, target := range []struct {
		path  string
		match func(map[string]any) bool
	}{
		{path: "/queue/simple", match: func(item map[string]any) bool {
			name, _ := item["name"].(string)
			return name == "local-auth-"+compactMAC
		}},
		{path: "/ip/hotspot/ip-binding", match: func(item map[string]any) bool {
			itemMAC, _ := item["mac-address"].(string)
			comment, _ := item["comment"].(string)
			return strings.EqualFold(itemMAC, mac) && strings.HasPrefix(comment, "local-auth expires=")
		}},
		{path: "/ip/firewall/address-list", match: func(item map[string]any) bool {
			comment, _ := item["comment"].(string)
			return strings.Contains(comment, "mac="+mac) && strings.HasPrefix(comment, "local-auth expires=")
		}},
	} {
		var items []map[string]any
		if err := a.router.get(target.path, &items); err != nil {
			return fmt.Errorf("list %s: %w", target.path, err)
		}
		for _, item := range items {
			if !target.match(item) {
				continue
			}
			id, ok := item[".id"].(string)
			if !ok || id == "" {
				continue
			}
			if err := a.router.delete(target.path + "/" + id); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("delete %s: %w", target.path, err)
			}
		}
	}
	return firstErr
}

func (a *app) expireGrant(req request, until time.Time) {
	if delay := time.Until(until); delay > 0 {
		time.Sleep(delay)
	}
	var lastErr error
	for attempt := 1; attempt <= 10; attempt++ {
		if err := a.revokeGrantAt(req.MAC, until.Unix()); err == nil {
			a.logEvent(map[string]any{"type": "access_expired", "client_ip": req.ClientIP, "mac": req.MAC, "expires_unix": until.Unix()})
			return
		} else {
			lastErr = err
		}
		time.Sleep(30 * time.Second)
	}
	a.logEvent(map[string]any{"type": "access_expiry_error", "client_ip": req.ClientIP, "mac": req.MAC, "expires_unix": until.Unix(), "error": lastErr.Error()})
}

func (a *app) restoreActiveGrants() {
	var items []map[string]any
	if err := a.router.get("/ip/hotspot/ip-binding", &items); err != nil {
		log.Printf("restore local-auth grants: %v", err)
		return
	}
	now := time.Now().Unix()
	for _, item := range items {
		until, ok := localAuthExpiry(item)
		mac, _ := item["mac-address"].(string)
		address, _ := item["address"].(string)
		if !ok || until <= now || mac == "" || address == "" {
			continue
		}
		req := request{ClientIP: address, MAC: mac}
		if err := a.addApprovedGuest(req, time.Unix(until, 0), "local-auth expires="+strconv.FormatInt(until, 10)); err != nil {
			log.Printf("restore local-auth firewall permission for %s: %v", mac, err)
			continue
		}
		go a.expireGrant(req, time.Unix(until, 0))
	}
}

func (a *app) revokeGrantAt(mac string, expiresUnix int64) error {
	compactMAC := strings.ReplaceAll(strings.ToLower(mac), ":", "")
	var firstErr error
	for _, target := range []struct {
		path  string
		match func(map[string]any) bool
	}{
		{path: "/queue/simple", match: func(item map[string]any) bool {
			name, _ := item["name"].(string)
			until, ok := localAuthExpiry(item)
			return name == "local-auth-"+compactMAC && ok && until == expiresUnix
		}},
		{path: "/ip/hotspot/ip-binding", match: func(item map[string]any) bool {
			itemMAC, _ := item["mac-address"].(string)
			until, ok := localAuthExpiry(item)
			return strings.EqualFold(itemMAC, mac) && ok && until == expiresUnix
		}},
		{path: "/ip/firewall/address-list", match: func(item map[string]any) bool {
			comment, _ := item["comment"].(string)
			until, ok := localAuthExpiry(item)
			return strings.Contains(comment, "mac="+mac) && ok && until == expiresUnix
		}},
	} {
		var items []map[string]any
		if err := a.router.get(target.path, &items); err != nil {
			return fmt.Errorf("list %s: %w", target.path, err)
		}
		for _, item := range items {
			if !target.match(item) {
				continue
			}
			id, ok := item[".id"].(string)
			if !ok || id == "" {
				continue
			}
			if err := a.router.delete(target.path + "/" + id); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("delete %s: %w", target.path, err)
			}
		}
	}
	return firstErr
}

func localAuthExpiry(item map[string]any) (int64, bool) {
	comment, ok := item["comment"].(string)
	if !ok || !strings.HasPrefix(comment, "local-auth ") {
		return 0, false
	}
	for _, part := range strings.Fields(comment) {
		if strings.HasPrefix(part, "expires=") {
			until, err := strconv.ParseInt(strings.TrimPrefix(part, "expires="), 10, 64)
			return until, err == nil
		}
	}
	return 0, false
}

func localAuthQuota(item map[string]any) (uint64, bool) {
	comment, ok := item["comment"].(string)
	if !ok || !strings.HasPrefix(comment, "local-auth ") {
		return 0, false
	}
	for _, part := range strings.Fields(comment) {
		if strings.HasPrefix(part, "quota=") {
			quota, err := strconv.ParseUint(strings.TrimPrefix(part, "quota="), 10, 64)
			return quota, err == nil
		}
	}
	return 0, false
}

func queueByteTotal(value any) (uint64, bool) {
	raw, ok := value.(string)
	if !ok {
		return 0, false
	}
	parts := strings.Split(raw, "/")
	if len(parts) != 2 {
		return 0, false
	}
	var total uint64
	for _, part := range parts {
		bytes, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return 0, false
		}
		total += bytes
	}
	return total, true
}

func queueMAC(name string) string {
	compact := strings.TrimPrefix(name, "local-auth-")
	if len(compact) != 12 {
		return ""
	}
	var parts []string
	for i := 0; i < len(compact); i += 2 {
		part := compact[i : i+2]
		if _, err := strconv.ParseUint(part, 16, 8); err != nil {
			return ""
		}
		parts = append(parts, strings.ToUpper(part))
	}
	return strings.Join(parts, ":")
}

func (c client) put(path string, body any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPut, c.base+"/rest"+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.SetBasicAuth(c.user, c.pass)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return fmt.Errorf("%s", response.Status)
	}
	return nil
}

func (c client) get(path string, out any) error {
	request, err := http.NewRequest(http.MethodGet, c.base+"/rest"+path, nil)
	if err != nil {
		return err
	}
	request.SetBasicAuth(c.user, c.pass)
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return fmt.Errorf("%s", response.Status)
	}
	return json.NewDecoder(response.Body).Decode(out)
}

func (c client) delete(path string) error {
	request, err := http.NewRequest(http.MethodDelete, c.base+"/rest"+path, nil)
	if err != nil {
		return err
	}
	request.SetBasicAuth(c.user, c.pass)
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return fmt.Errorf("%s", response.Status)
	}
	return nil
}

func formContext(r *http.Request) (string, string) {
	ip := r.FormValue("client_ip")
	if !validIP(ip) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip = host
	}
	return ip, normalizeMAC(r.FormValue("mac"))
}

func validIP(value string) bool { return net.ParseIP(strings.TrimSpace(value)) != nil }

func normalizeMAC(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if macRE.MatchString(value) {
		return value
	}
	return ""
}

func normalizePhone(value string) string {
	value = strings.TrimSpace(value)
	var digits strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		}
	}
	number := digits.String()
	if strings.HasPrefix(value, "+") && len(number) >= 10 && len(number) <= 15 {
		return "+" + number
	}
	if len(number) == 10 {
		return "+7" + number
	}
	if len(number) == 11 && (number[0] == '7' || number[0] == '8') {
		return "+7" + number[1:]
	}
	return ""
}

func randomID() (string, error) {
	number, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("G-%06d", number.Int64()+100000), nil
}

func randomSMSCode() (string, error) {
	number, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", number.Int64()), nil
}

func maskPhone(phone string) string {
	if len(phone) < 6 {
		return "SMS"
	}
	return phone[:2] + strings.Repeat("*", len(phone)-6) + phone[len(phone)-4:]
}

func (a *app) logEvent(fields map[string]any) {
	now := time.Now().UTC()
	fields["time_utc"] = now.Format(time.RFC3339Nano)
	line, err := json.Marshal(fields)
	if err != nil {
		return
	}
	a.logMu.Lock()
	defer a.logMu.Unlock()
	dir := filepath.Dir(a.cfg.LogPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	path := filepath.Join(dir, "approval-"+now.Format("2006-01-02")+".jsonl")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.Write(append(line, '\n'))
}

// User-facing access times are always Moscow time; audit timestamps remain UTC.
func displayMoscowTime(value time.Time) string {
	return value.In(moscowLocation).Format("15:04")
}

func (a *app) errorPage(w http.ResponseWriter, message string) {
	a.page(w, "Ошибка", "<h1>Ошибка</h1><p>"+html.EscapeString(message)+"</p>")
}

func (a *app) page(w http.ResponseWriter, title, body string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title><style>body{margin:0;background:#f3f4f6;font:17px Arial;color:#111}main{max-width:420px;margin:36px auto;background:#fff;padding:24px;border-radius:10px}input,button{width:100%%;box-sizing:border-box;font-size:17px;padding:13px;margin-top:12px}button{border:0;border-radius:8px;background:#1677ff;color:#fff;font-weight:600;min-height:48px;cursor:pointer}button:disabled{opacity:.65;cursor:wait}form{margin:0}.actions{display:grid;gap:12px;margin-top:20px}.actions button{margin-top:0}.notice{font-size:14px;line-height:1.4;color:#444;margin:18px 0;padding:12px;background:#f7f8fa;border-left:3px solid #1677ff}.phone{display:flex;align-items:end;gap:8px}.phone span{padding:13px 0;font-weight:600}.phone input{margin-top:12px}</style></head><body><main>%s</main></body></html>`, html.EscapeString(title), body)
}

var _ = io.EOF
