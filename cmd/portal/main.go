package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type config struct {
	ListenAddr, GarageURL, GarageUser, GaragePassword, HotspotServer, GuestRateLimit string
	GrantMinutes                                                                     int
	RequestTTL                                                                       time.Duration
	AdminUser, AdminPassword, LogPath                                                string
	AdminCIDR                                                                        *net.IPNet
}

type request struct {
	ID, ClientIP, MAC        string
	CreatedAt, ExpiresAt     time.Time
	ApprovedAt, GrantedUntil time.Time
}

type app struct {
	cfg     config
	router  client
	mu      sync.Mutex
	pending map[string]request
}

type client struct {
	base, user, pass string
	http             *http.Client
}

var macRE = regexp.MustCompile(`^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$`)

func main() {
	a := newApp()
	go a.cleanup()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.health)
	mux.HandleFunc("/", a.home)
	mux.HandleFunc("/request", a.request)
	mux.HandleFunc("/status", a.status)
	mux.HandleFunc("/admin", a.admin)
	mux.HandleFunc("/approve", a.approve)
	log.Fatal(http.ListenAndServe(a.cfg.ListenAddr, mux))
}

func newApp() *app {
	_, cidr, _ := net.ParseCIDR(env("ADMIN_CIDR", "192.168.50.0/24"))
	cfg := config{
		ListenAddr: env("LISTEN_ADDR", ":8080"), GarageURL: strings.TrimRight(env("GARAGE_ROUTER_URL", "http://192.168.50.1"), "/"),
		GarageUser: env("GARAGE_ROUTER_USER", "approval-api"), GaragePassword: env("GARAGE_ROUTER_PASSWORD", ""),
		HotspotServer: env("HOTSPOT_SERVER", "hotspot-guest"), GuestRateLimit: env("GUEST_RATE_LIMIT", "5M/20M"),
		GrantMinutes: num("GRANT_MINUTES", 60), RequestTTL: time.Duration(num("REQUEST_TTL_SECONDS", 600)) * time.Second,
		AdminUser: env("ADMIN_USER", "master"), AdminPassword: env("ADMIN_PASSWORD", ""), AdminCIDR: cidr,
		LogPath: env("LOG_PATH", "/data/approval.log"),
	}
	return &app{
		cfg:     cfg,
		router:  client{base: cfg.GarageURL, user: cfg.GarageUser, pass: cfg.GaragePassword, http: &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}},
		pending: map[string]request{},
	}
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

func (a *app) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("OK"))
}

func (a *app) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	ip, mac := formContext(r)
	a.page(w, "Гостевой Wi-Fi", fmt.Sprintf(`<h1>Гостевой Wi-Fi</h1><p>Отправьте заявку мастеру. Доступ будет открыт после подтверждения.</p><form method="post" action="/request"><input type="hidden" name="client_ip" value="%s"><input type="hidden" name="mac" value="%s"><button>Запросить доступ</button></form>`, html.EscapeString(ip), html.EscapeString(mac)))
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
			a.page(w, "Доступ открыт", fmt.Sprintf(`<h1>Доступ открыт</h1><p>Мастер подтвердил заявку. Доступ действует до %s.</p>`, req.GrantedUntil.Local().Format("15:04")))
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

	a.mu.Lock()
	req.ApprovedAt = time.Now().UTC()
	req.GrantedUntil = until
	a.pending[id] = req
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
	until := time.Now().Add(time.Duration(a.cfg.GrantMinutes) * time.Minute).UTC()
	comment := fmt.Sprintf("local-auth expires=%d", until.Unix())
	name := "local-auth-" + strings.ReplaceAll(strings.ToLower(req.MAC), ":", "")
	queue := map[string]string{"name": name, "target": req.ClientIP + "/32", "max-limit": a.cfg.GuestRateLimit, "comment": comment + " mac=" + req.MAC}
	if err := a.router.put("/queue/simple", queue); err != nil {
		return time.Time{}, err
	}
	binding := map[string]string{"server": a.cfg.HotspotServer, "address": req.ClientIP, "mac-address": req.MAC, "type": "bypassed", "comment": comment}
	if err := a.router.put("/ip/hotspot/ip-binding", binding); err != nil {
		return time.Time{}, err
	}
	return until, nil
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

func (a *app) authorizeAdmin(w http.ResponseWriter, r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || a.cfg.AdminCIDR == nil || !a.cfg.AdminCIDR.Contains(net.ParseIP(host)) {
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

func (a *app) cleanup() {
	a.cleanupOnce()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		a.cleanupOnce()
	}
}

func (a *app) cleanupOnce() {
	now := time.Now().UTC()
	a.mu.Lock()
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
	a.mu.Unlock()
	if err := a.cleanupExpiredGrants(now.Unix()); err != nil {
		log.Printf("local-auth cleanup: %v", err)
	}
}

func (a *app) cleanupExpiredGrants(now int64) error {
	if a.cfg.GaragePassword == "" {
		return nil
	}
	for _, target := range []struct {
		path       string
		logRemoval bool
	}{
		{path: "/queue/simple"},
		{path: "/ip/hotspot/ip-binding", logRemoval: true},
	} {
		var items []map[string]any
		if err := a.router.get(target.path, &items); err != nil {
			return err
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
			if err := a.router.delete(target.path + "/" + url.PathEscape(id)); err != nil {
				return err
			}
			if target.logRemoval {
				a.logEvent(map[string]any{"type": "access_expired", "client_ip": item["address"], "mac": item["mac-address"], "expires_unix": until})
			}
		}
	}
	return nil
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

func randomID() (string, error) {
	number, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("G-%06d", number.Int64()+100000), nil
}

func (a *app) logEvent(fields map[string]any) {
	fields["time_utc"] = time.Now().UTC().Format(time.RFC3339Nano)
	line, err := json.Marshal(fields)
	if err != nil {
		return
	}
	dir := filepath.Dir(a.cfg.LogPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	path := filepath.Join(dir, "approval-"+time.Now().UTC().Format("2006-01")+".jsonl")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.Write(append(line, '\n'))
}

func (a *app) errorPage(w http.ResponseWriter, message string) {
	a.page(w, "Ошибка", "<h1>Ошибка</h1><p>"+html.EscapeString(message)+"</p>")
}

func (a *app) page(w http.ResponseWriter, title, body string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title><style>body{margin:0;background:#f3f4f6;font:17px Arial;color:#111}main{max-width:420px;margin:36px auto;background:#fff;padding:24px;border-radius:10px}input,button{width:100%%;box-sizing:border-box;font-size:17px;padding:13px;margin-top:12px}button{border:0;border-radius:8px;background:#1677ff;color:#fff}section{border-top:1px solid #ddd;padding:14px 0}</style></head><body><main>%s</main></body></html>`, html.EscapeString(title), body)
}

var _ = io.EOF

