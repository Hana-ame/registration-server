// reg-server —— peerdrive 注册/认证服务器（重写版 2026-09-24）
//
// 背景：原 reg-server 源码丢失（GitHub 只有历史分支里的编译产物 blob，
// 本地/三台主机均无源码）。按用户要求重写，行为与现行二进制完全兼容：
//
//   - 路由面（2026-09-24 对 cloudcone 现行实例逐个采样对齐）：
//     GET  /ping                     -> {"service":"peerdrive-registration","status":"ok"}               （无认证）
//     GET  /api/health               -> 认证后 200                                                     （需 Bearer）
//     POST /auth/register            -> {token, username}                                              （无认证）
//     POST /auth/login               -> {token}                                                        （无认证）
//     GET  /auth/whoami              -> {role, username}；无/坏 token 401                              （需 Bearer）
//     GET  /auth/list                -> 认证后 {"users":[...]}                                          （需 Bearer）
//     POST /p2p/relay/register       -> {"status":"registered"}，peer_id 必填否则 400                   （无认证）
//     POST /p2p/relay/heartbeat      -> {"status":"ok"}                                                 （无认证）
//     GET  /p2p/relay/list           -> {"relays":[...]}                                                 （无认证）
//   - 数据库：直接复用既有 /root/reg-storage/reg.db（表 users / relay_nodes，
//     密码 bcrypt cost 10，旧用户与已发 JWT 全部兼容）
//   - JWT：HS256，claims {username, role, iss, sub, exp, iat}，TTL 3 天，
//     与旧 token 同密钥（JWT_SECRET）时旧 token 直接可验
//   - 新增 HOST 环境变量：指定监听 IP（如 HOST=127.26.9.24 PORT=8080）；
//     空 HOST = 全网卡 :PORT（与旧版一致）
//
// 构建：GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o reg-server .
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	_ "modernc.org/sqlite"
)

// ---------------------------------------------------------------------------
// JSON 工具

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// ---------------------------------------------------------------------------
// JWT（HS256，手写实现，与旧服务兼容）

var jwtSecret []byte

const tokenTTL = 72 * time.Hour // 旧 token TTL=3 天（实测 bwh 签发 token exp-iat=259200s）

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newToken(username, role string) (string, error) {
	now := time.Now()
	claims := map[string]any{
		"username": username,
		"role":     role,
		"iss":      "https://localhost:4000", // 与旧服务一致
		"sub":      username,
		"iat":      now.Unix(),
		"exp":      now.Add(tokenTTL).Unix(),
	}
	hb, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	h := b64url(hb)
	p := b64url(pb)
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(h + "." + p))
	return h + "." + p + "." + b64url(mac.Sum(nil)), nil
}

// verifyToken 验签并提取 claims；返回 (username, role, error)。
func verifyToken(tok string) (string, string, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", "", errors.New("invalid or expired token")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", "", errors.New("invalid or expired token")
	}
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return "", "", errors.New("invalid or expired token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", errors.New("invalid or expired token")
	}
	var claims struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		Exp      int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", errors.New("invalid or expired token")
	}
	if claims.Exp != 0 && time.Now().Unix() > claims.Exp {
		return "", "", errors.New("invalid or expired token")
	}
	return claims.Username, claims.Role, nil
}

// ---------------------------------------------------------------------------
// 认证中间件

type authCtxKey struct{}

type authInfo struct{ username, role string }

// authRequired 从 Authorization: Bearer 头取 token 验证；失败 401（与旧服务同文案）。
func authRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if h == "" {
			writeErr(w, http.StatusUnauthorized, "missing authorization header")
			return
		}
		parts := strings.SplitN(h, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			writeErr(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		user, role, err := verifyToken(parts[1])
		if err != nil {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		ctx := context.WithValue(r.Context(), authCtxKey{}, authInfo{user, role})
		next(w, r.WithContext(ctx))
	}
}

func authInfoOf(r *http.Request) authInfo {
	if v, ok := r.Context().Value(authCtxKey{}).(authInfo); ok {
		return v
	}
	return authInfo{}
}

// ---------------------------------------------------------------------------
// 数据库

var db *sql.DB

func openDB(path string) error {
	d, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return err
	}
	if err := d.Ping(); err != nil {
		return err
	}
	// 表缺失时按旧 schema 创建（沿用既有库时不会动已有表）。
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS relay_nodes (
			peer_id TEXT PRIMARY KEY,
			addrs TEXT NOT NULL,
			storage_mb INTEGER DEFAULT 0,
			load_pct REAL DEFAULT 0,
			version TEXT DEFAULT '',
			registered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_heartbeat DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, s := range stmts {
		if _, err := d.Exec(s); err != nil {
			return err
		}
	}
	db = d
	return nil
}

// ---------------------------------------------------------------------------
// handlers

func apiHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func apiPing(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"service": "peerdrive-registration", "status": "ok"})
}

func authRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Username) == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "username and password required")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost) // cost 10，与旧库一致
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if _, err := db.Exec(`INSERT INTO users(username, password_hash, role) VALUES(?, ?, 'user')`,
		req.Username, string(hash)); err != nil {
		writeErr(w, http.StatusConflict, "username already exists")
		return
	}
	tok, err := newToken(req.Username, "user")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": req.Username, "token": tok})
}

func authLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	var hash, role string
	err := db.QueryRow(`SELECT password_hash, role FROM users WHERE username = ?`, req.Username).Scan(&hash, &role)
	if errors.Is(err, sql.ErrNoRows) || bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		writeErr(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	tok, err := newToken(req.Username, role)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": tok})
}

func authWhoami(w http.ResponseWriter, r *http.Request) {
	u := authInfoOf(r)
	var role string
	if err := db.QueryRow(`SELECT role FROM users WHERE username = ?`, u.username).Scan(&role); err != nil {
		role = u.role
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": u.username, "role": role})
}

func authList(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`SELECT username, role FROM users ORDER BY id`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()
	type u struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	var out []u
	for rows.Next() {
		var x u
		if rows.Scan(&x.Username, &x.Role) == nil {
			out = append(out, x)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

// ---- relay ----

func relayRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PeerID    string  `json:"peer_id"`
		Addrs     any     `json:"addrs"`
		StorageMB int64   `json:"storage_mb"`
		LoadPct   float64 `json:"load_pct"`
		Version   string  `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if strings.TrimSpace(req.PeerID) == "" {
		writeErr(w, http.StatusBadRequest, "peer_id is required")
		return
	}
	addrs := stringifyAddrs(req.Addrs)
	if _, err := db.Exec(`INSERT INTO relay_nodes(peer_id, addrs, storage_mb, load_pct, version)
		VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(peer_id) DO UPDATE SET
			addrs=excluded.addrs, storage_mb=excluded.storage_mb,
			load_pct=excluded.load_pct, version=excluded.version,
			last_heartbeat=CURRENT_TIMESTAMP`,
		req.PeerID, addrs, req.StorageMB, req.LoadPct, req.Version); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "registered"})
}

func relayHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PeerID string `json:"peer_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.PeerID == "" {
		writeErr(w, http.StatusBadRequest, "peer_id is required")
		return
	}
	_, _ = db.Exec(`UPDATE relay_nodes SET last_heartbeat = CURRENT_TIMESTAMP WHERE peer_id = ?`, req.PeerID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func relayList(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`SELECT peer_id, addrs, storage_mb, load_pct, version, registered_at, last_heartbeat FROM relay_nodes`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()
	type node struct {
		PeerID        string  `json:"peer_id"`
		Addrs         any     `json:"addrs"`
		StorageMB     int64   `json:"storage_mb"`
		LoadPct       float64 `json:"load_pct"`
		Version       string  `json:"version"`
		RegisteredAt  string  `json:"registered_at"`
		LastHeartbeat string  `json:"last_heartbeat"`
	}
	var out []node
	for rows.Next() {
		var n node
		var addrs string
		if rows.Scan(&n.PeerID, &addrs, &n.StorageMB, &n.LoadPct, &n.Version, &n.RegisteredAt, &n.LastHeartbeat) != nil {
			continue
		}
		n.Addrs = parseAddrs(addrs)
		out = append(out, n)
	}
	writeJSON(w, http.StatusOK, map[string]any{"relays": out})
}

func stringifyAddrs(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if b, err := json.Marshal(v); err == nil {
		return string(b)
	}
	return ""
}

func parseAddrs(s string) any {
	if s == "" {
		return nil
	}
	var arr []string
	if json.Unmarshal([]byte(s), &arr) == nil {
		return arr
	}
	return s
}

// ---------------------------------------------------------------------------
// main

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "4000"
	}
	host := os.Getenv("HOST") // 重写新增：指定监听 IP；空 = 全网卡（与旧版 :PORT 一致）
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "./reg.db"
	}
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		fmt.Fprintln(os.Stderr, "JWT_SECRET is required")
		os.Exit(1)
	}
	jwtSecret = []byte(secret)

	if err := openDB(dbPath); err != nil {
		fmt.Fprintf(os.Stderr, "db open failed: %v\n", err)
		os.Exit(1)
	}

	addr := ":" + port
	if host != "" {
		addr = net.JoinHostPort(host, port)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", apiPing)
	mux.HandleFunc("GET /api/health", authRequired(apiHealth))
	mux.HandleFunc("POST /auth/register", authRegister)
	mux.HandleFunc("POST /auth/login", authLogin)
	mux.HandleFunc("GET /auth/whoami", authRequired(authWhoami))
	mux.HandleFunc("GET /auth/list", authRequired(authList))
	mux.HandleFunc("POST /p2p/relay/register", relayRegister)
	mux.HandleFunc("POST /p2p/relay/heartbeat", relayHeartbeat)
	mux.HandleFunc("GET /p2p/relay/list", relayList)

	fmt.Printf("Registration server starting on %s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start: %v\n", err)
		os.Exit(1)
	}
}