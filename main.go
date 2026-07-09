package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed index.html
var embedFS embed.FS

// Config stores configurations loaded from Env
type Config struct {
	DockerSocket     string
	Host             string
	Port             string
	TelegramBotToken string
	TelegramChatID   string
}

// PruneConfig stores smart prune configuration
type PruneConfig struct {
	Enabled       bool  `json:"enabled"`
	IntervalHours int   `json:"interval_hours"`
	LastPruneTime int64 `json:"last_prune_time"`
	// Per-resource toggles
	PruneContainers bool `json:"prune_containers"`
	PruneImages     bool `json:"prune_images"`
	PruneNetworks   bool `json:"prune_networks"`
	PruneVolumes    bool `json:"prune_volumes"`     // Default OFF — dangerous
	DanglingOnly    bool `json:"dangling_only"`     // Default ON — only dangling images
	KeepRecentHours int  `json:"keep_recent_hours"` // Keep items newer than N hours
}

// PruneResult stores the result of a prune operation per resource type
type PruneResult struct {
	ContainersDeleted []string `json:"containersDeleted"`
	ImagesDeleted     []string `json:"imagesDeleted"`
	NetworksDeleted   []string `json:"networksDeleted"`
	VolumesDeleted    []string `json:"volumesDeleted"`
	SpaceReclaimed    uint64   `json:"spaceReclaimed"` // bytes
}

// PrunePreviewItem represents a single item that would be pruned
type PrunePreviewItem struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Type  string `json:"type"`            // container, image, network, volume
	Size  int64  `json:"size"`            // bytes, -1 if unknown
	Age   string `json:"age"`             // human readable
	Extra string `json:"extra,omitempty"` // e.g. image tag, exit code
}

// PrunePreview is the full preview response
type PrunePreview struct {
	Containers     []PrunePreviewItem `json:"containers"`
	Images         []PrunePreviewItem `json:"images"`
	Networks       []PrunePreviewItem `json:"networks"`
	Volumes        []PrunePreviewItem `json:"volumes"`
	TotalItems     int                `json:"totalItems"`
	EstimatedSpace int64              `json:"estimatedSpace"` // bytes
}

// Docker API prune response structures
type dockerPruneContainersResp struct {
	ContainersDeleted []string `json:"ContainersDeleted"`
	SpaceReclaimed    uint64   `json:"SpaceReclaimed"`
}
type dockerPruneImagesResp struct {
	ImagesDeleted []struct {
		Deleted  string `json:"Deleted,omitempty"`
		Untagged string `json:"Untagged,omitempty"`
	} `json:"ImagesDeleted"`
	SpaceReclaimed uint64 `json:"SpaceReclaimed"`
}
type dockerPruneNetworksResp struct {
	NetworksDeleted []string `json:"NetworksDeleted"`
}
type dockerPruneVolumesResp struct {
	VolumesDeleted []string `json:"VolumesDeleted"`
	SpaceReclaimed uint64   `json:"SpaceReclaimed"`
}

// AppConfig stores the password hash, salt, and telegram alert configs
type AppConfig struct {
	PasswordHash     string      `json:"password_hash"`
	Salt             string      `json:"salt"`
	TelegramBotToken string      `json:"telegram_bot_token"`
	TelegramChatID   string      `json:"telegram_chat_id"`
	TelegramDisabled bool        `json:"telegram_disabled"`
	TelegramAdminID  string      `json:"telegram_admin_id"`
	Prune            PruneConfig `json:"prune"`
	// Legacy fields for backward compatibility (will be migrated on load)
	PruneEnabled       bool  `json:"prune_enabled,omitempty"`
	PruneIntervalHours int   `json:"prune_interval_hours,omitempty"`
	LastPruneTime      int64 `json:"last_prune_time,omitempty"`
}

var config Config
var appConfig AppConfig
var configPath string
var diskPath string
var setupToken string

var dockerClient *http.Client
var updateTriggerChan = make(chan struct{}, 10)

// SSE Client manager
type SSEManager struct {
	clients map[chan string]bool
	mu      sync.Mutex
}

var sseManager = SSEManager{
	clients: make(map[chan string]bool),
}

// Session store
var (
	sessions   = make(map[string]time.Time)
	sessionsMu sync.RWMutex
)

// Login Rate Limiter for security
type LoginLimiter struct {
	attempts map[string]int
	lockouts map[string]time.Time
	mu       sync.Mutex
}

var loginLimiter = LoginLimiter{
	attempts: make(map[string]int),
	lockouts: make(map[string]time.Time),
}

func getClientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func isIPLocked(ip string) bool {
	loginLimiter.mu.Lock()
	defer loginLimiter.mu.Unlock()

	if unlockTime, ok := loginLimiter.lockouts[ip]; ok {
		if time.Now().Before(unlockTime) {
			return true
		}
		// Lock expired
		delete(loginLimiter.lockouts, ip)
		delete(loginLimiter.attempts, ip)
	}
	return false
}

func recordFailedLogin(ip string) {
	loginLimiter.mu.Lock()
	defer loginLimiter.mu.Unlock()

	loginLimiter.attempts[ip]++
	if loginLimiter.attempts[ip] >= 5 {
		loginLimiter.lockouts[ip] = time.Now().Add(15 * time.Minute)
		log.Printf("[SECURITY] IP %s is locked out for 15 minutes due to too many failed login attempts.", ip)
	}
}

func recordSuccessfulLogin(ip string) {
	loginLimiter.mu.Lock()
	defer loginLimiter.mu.Unlock()

	delete(loginLimiter.attempts, ip)
	delete(loginLimiter.lockouts, ip)
}

// Resource Alert Lock states
var (
	cpuAlertActive    bool
	ramAlertActive    bool
	diskAlertActive   bool
	cpuOverLimitCount int
)

// Flap tracking to prevent Telegram spam
type FlapTracker struct {
	timestamps []time.Time
	mutedUntil time.Time
}

var (
	flapTrackers   = make(map[string]*FlapTracker)
	flapTrackersMu sync.Mutex
)


// Docker API Structures
type Container struct {
	ID      string   `json:"Id"`
	Names   []string `json:"Names"`
	Image   string   `json:"Image"`
	State   string   `json:"State"`
	Status  string   `json:"Status"`
	Created int64    `json:"Created"`
}

type ContainerStats struct {
	MemoryStats struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
}

type DockerEvent struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
	Time int64 `json:"time"`
}

// Custom UI structures to push
type ContainerUI struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Image      string  `json:"image"`
	State      string  `json:"state"`
	Status     string  `json:"status"`
	RAMUsed    float64 `json:"ramUsed"`    // in MB
	RAMLimit   float64 `json:"ramLimit"`   // in MB
	RAMPercent float64 `json:"ramPercent"` // %
}

type HostStats struct {
	CPUUsage    float64 `json:"cpuUsage"`
	RAMUsed     float64 `json:"ramUsed"`     // in GB
	RAMTotal    float64 `json:"ramTotal"`    // in GB
	RAMPercent  float64 `json:"ramPercent"`  // %
	DiskUsed    float64 `json:"diskUsed"`    // in GB
	DiskTotal   float64 `json:"diskTotal"`   // in GB
	DiskPercent float64 `json:"diskPercent"` // %
}

type StatsSummary struct {
	TotalContainers int           `json:"totalContainers"`
	RunningCount    int           `json:"runningCount"`
	StoppedCount    int           `json:"stoppedCount"`
	Containers      []ContainerUI `json:"containers"`
	Host            HostStats     `json:"host"`
}

func initDockerClient() {
	socketPath := config.DockerSocket
	dockerClient = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}
}

func fetchContainerStats(ctx context.Context, c Container) ContainerUI {
	ui := ContainerUI{
		ID:     c.ID[:12],
		Name:   c.Image,
		Image:  c.Image,
		State:  c.State,
		Status: c.Status,
	}

	if len(c.Names) > 0 {
		ui.Name = c.Names[0]
		if strings.HasPrefix(ui.Name, "/") {
			ui.Name = ui.Name[1:]
		}
	}

	if c.State != "running" {
		return ui
	}

	reqURL := fmt.Sprintf("http://localhost/containers/%s/stats?stream=false", c.ID)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return ui
	}

	resp, err := dockerClient.Do(req)
	if err != nil {
		return ui
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ui
	}

	var stats ContainerStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return ui
	}

	used := stats.MemoryStats.Usage
	if cache, ok := stats.MemoryStats.Stats["cache"]; ok {
		used -= cache
	} else if inactiveFile, ok := stats.MemoryStats.Stats["inactive_file"]; ok {
		used -= inactiveFile
	}

	limit := stats.MemoryStats.Limit

	ui.RAMUsed = float64(used) / (1024 * 1024)
	ui.RAMLimit = float64(limit) / (1024 * 1024)
	if limit > 0 {
		ui.RAMPercent = (float64(used) / float64(limit)) * 100
	}

	return ui
}

func getSystemState() (StatsSummary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := dockerClient.Get("http://localhost/containers/json?all=1")
	if err != nil {
		return StatsSummary{}, err
	}
	defer resp.Body.Close()

	var containers []Container
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return StatsSummary{}, err
	}

	summary := StatsSummary{
		TotalContainers: len(containers),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	containerUIs := make([]ContainerUI, len(containers))

	for i, c := range containers {
		if c.State == "running" {
			summary.RunningCount++
		} else {
			summary.StoppedCount++
		}

		wg.Add(1)
		go func(idx int, cnt Container) {
			defer wg.Done()
			ui := fetchContainerStats(ctx, cnt)
			mu.Lock()
			containerUIs[idx] = ui
			mu.Unlock()
		}(i, c)
	}

	wg.Wait()
	summary.Containers = containerUIs

	// Get Host Stats (CPU, RAM, Disk)
	cpuUsage, _ := getCPUUsage() // 500ms delay inside, acceptable since called in sseBroadcastLoop background

	ramTotal, ramAvailable, _ := getMemoryUsage()
	var ramUsed uint64
	var ramPercent float64
	if ramTotal > 0 {
		ramUsed = ramTotal - ramAvailable
		ramPercent = (float64(ramUsed) / float64(ramTotal)) * 100
	}

	diskTotal, diskFree, _ := getDiskUsage(diskPath)
	var diskUsed uint64
	var diskPercent float64
	if diskTotal > 0 {
		diskUsed = diskTotal - diskFree
		diskPercent = (float64(diskUsed) / float64(diskTotal)) * 100
	}

	summary.Host = HostStats{
		CPUUsage:    cpuUsage,
		RAMUsed:     float64(ramUsed) / (1024 * 1024 * 1024),
		RAMTotal:    float64(ramTotal) / (1024 * 1024 * 1024),
		RAMPercent:  ramPercent,
		DiskUsed:    float64(diskUsed) / (1024 * 1024 * 1024),
		DiskTotal:   float64(diskTotal) / (1024 * 1024 * 1024),
		DiskPercent: diskPercent,
	}

	return summary, nil
}

// Password verification helpers
func hashPassword(password, salt string) string {
	hasher := sha256.New()
	hasher.Write([]byte(password + salt))
	return hex.EncodeToString(hasher.Sum(nil))
}

func generateSalt() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Session store helpers
func createSession() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	sessionsMu.Lock()
	sessions[token] = time.Now().Add(24 * time.Hour)
	sessionsMu.Unlock()
	return token, nil
}

func validateSession(token string) bool {
	sessionsMu.RLock()
	expiry, ok := sessions[token]
	sessionsMu.RUnlock()

	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		sessionsMu.Lock()
		delete(sessions, token)
		sessionsMu.Unlock()
		return false
	}
	return true
}

func deleteSession(token string) {
	sessionsMu.Lock()
	delete(sessions, token)
	sessionsMu.Unlock()
}

// Authentication Middleware
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("DockerWhiz_session")
		if err != nil || !validateSession(cookie.Value) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// CSRF Prevention for modifying requests (POST, PUT, DELETE)
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			if r.Header.Get("X-DockerWhiz-Request") != "true" {
				http.Error(w, "Missing or invalid custom safety header (CSRF protection)", http.StatusBadRequest)
				return
			}
		}

		next(w, r)
	}
}

// Load and Save config
func loadConfig() {
	configPath = getEnv("CONFIG_PATH", "./config.json")

	// Check if path is a directory (common Docker mounting mistake)
	if info, err := os.Stat(configPath); err == nil && info.IsDir() {
		log.Fatalf("Failed to load configuration: CONFIG_PATH (%s) is a directory. If you are using Docker, please check your volume mount (-v). You should mount a file, or preferably mount a data folder instead.", configPath)
	}

	file, err := os.Open(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("Configuration file not found. Setup Mode active.")
			return
		}
		log.Fatalf("Failed to open configuration file: %v", err)
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&appConfig); err != nil {
		log.Fatalf("Failed to parse configuration file: %v", err)
	}

	// Backward compatibility: migrate old flat prune fields to new PruneConfig
	migrated := false
	if appConfig.PruneEnabled && !appConfig.Prune.Enabled {
		appConfig.Prune.Enabled = appConfig.PruneEnabled
		appConfig.Prune.IntervalHours = appConfig.PruneIntervalHours
		appConfig.Prune.LastPruneTime = appConfig.LastPruneTime
		// Safe defaults for new fields
		appConfig.Prune.PruneContainers = true
		appConfig.Prune.PruneImages = true
		appConfig.Prune.PruneNetworks = true
		appConfig.Prune.PruneVolumes = false // SAFE: don't auto-delete volumes
		appConfig.Prune.DanglingOnly = true  // SAFE: only dangling images
		appConfig.Prune.KeepRecentHours = 24
		// Clear legacy fields
		appConfig.PruneEnabled = false
		appConfig.PruneIntervalHours = 0
		appConfig.LastPruneTime = 0
		migrated = true
		log.Println("[CONFIG] Migrated legacy prune settings to new PruneConfig format.")
	} else if appConfig.LastPruneTime != 0 && appConfig.Prune.LastPruneTime == 0 {
		// Partial migration: just the timestamp
		appConfig.Prune.LastPruneTime = appConfig.LastPruneTime
		appConfig.LastPruneTime = 0
		migrated = true
	}

	// Ensure safe defaults if PruneConfig is brand new (all zero values)
	if appConfig.Prune.KeepRecentHours == 0 {
		appConfig.Prune.KeepRecentHours = 24
	}

	if migrated {
		_ = saveConfig()
	}

	log.Println("Configuration loaded successfully. Authentication required.")
}

func saveConfig() error {
	file, err := os.Create(configPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(appConfig)
}

// Auth Handlers
func authStatusHandler(w http.ResponseWriter, r *http.Request) {
	setupRequired := appConfig.PasswordHash == ""
	cookie, err := r.Cookie("DockerWhiz_session")
	authenticated := err == nil && validateSession(cookie.Value)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"setupRequired": setupRequired,
		"authenticated": authenticated,
	})
}

func authSetupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-DockerWhiz-Request") != "true" {
		http.Error(w, "Missing or invalid custom safety header (CSRF protection)", http.StatusBadRequest)
		return
	}

	if appConfig.PasswordHash != "" {
		http.Error(w, "Setup already completed", http.StatusBadRequest)
		return
	}

	var req struct {
		Password string `json:"password"`
		Token    string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024*1024)).Decode(&req); err != nil || req.Password == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Verify Setup Token in a constant-time manner
	if setupToken == "" || req.Token == "" || subtle.ConstantTimeCompare([]byte(req.Token), []byte(setupToken)) != 1 {
		http.Error(w, "Invalid setup token", http.StatusForbidden)
		return
	}

	salt, err := generateSalt()
	if err != nil {
		http.Error(w, "Internal server error during salt generation", http.StatusInternalServerError)
		return
	}
	hash := hashPassword(req.Password, salt)

	appConfig.PasswordHash = hash
	appConfig.Salt = salt

	if err := saveConfig(); err != nil {
		http.Error(w, "Failed to save config file", http.StatusInternalServerError)
		return
	}

	// Disable setup mode
	setupToken = ""

	token, err := createSession()
	if err != nil {
		http.Error(w, "Session creation failure", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, token)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true}`))
}

func authLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-DockerWhiz-Request") != "true" {
		http.Error(w, "Missing or invalid custom safety header (CSRF protection)", http.StatusBadRequest)
		return
	}

	ip := getClientIP(r)
	if isIPLocked(ip) {
		http.Error(w, "Too many failed login attempts. IP temporarily locked out.", http.StatusTooManyRequests)
		return
	}

	if appConfig.PasswordHash == "" {
		http.Error(w, "Setup required", http.StatusBadRequest)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024*1024)).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	expectedHash := hashPassword(req.Password, appConfig.Salt)
	// Secure constant-time comparison
	if subtle.ConstantTimeCompare([]byte(expectedHash), []byte(appConfig.PasswordHash)) != 1 {
		recordFailedLogin(ip)
		http.Error(w, "Incorrect password", http.StatusUnauthorized)
		return
	}

	recordSuccessfulLogin(ip)

	token, err := createSession()
	if err != nil {
		http.Error(w, "Session creation failure", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, token)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true}`))
}

func authLogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("DockerWhiz_session")
	if err == nil {
		deleteSession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "DockerWhiz_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true}`))
}

func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "DockerWhiz_session",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		MaxAge:   86400,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Telegram Helpers
func escapeMarkdown(text string) string {
	replacer := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"[", "\\[",
		"`", "\\`",
	)
	return replacer.Replace(text)
}

func getTelegramCredentials() (string, string) {
	if appConfig.TelegramDisabled {
		return "", ""
	}
	token := appConfig.TelegramBotToken
	if token == "" {
		token = config.TelegramBotToken
	}
	chatID := appConfig.TelegramChatID
	if chatID == "" {
		chatID = config.TelegramChatID
	}
	return token, chatID
}

func shouldThrottleContainer(container, token, chatID string) bool {
	if container == "" || token == "" || chatID == "" {
		return false
	}

	flapTrackersMu.Lock()
	defer flapTrackersMu.Unlock()

	tracker, exists := flapTrackers[container]
	if !exists {
		tracker = &FlapTracker{}
		flapTrackers[container] = tracker
	}

	now := time.Now()

	// Nếu đang bị mute, gia hạn thêm 5 phút tắt tiếng và bỏ qua thông báo
	if now.Before(tracker.mutedUntil) {
		tracker.mutedUntil = now.Add(5 * time.Minute)
		log.Printf("[THROTTLE] Container %s đang bị mute. Gia hạn thêm 5 phút (đến %v). Bỏ qua thông báo.", container, tracker.mutedUntil.Format("15:04:05"))
		return true
	}

	// Dọn dẹp các sự kiện cũ hơn 60 giây
	validTimestamps := []time.Time{}
	for _, t := range tracker.timestamps {
		if now.Sub(t) <= 60*time.Second {
			validTimestamps = append(validTimestamps, t)
		}
	}
	tracker.timestamps = append(validTimestamps, now)

	// Nếu tần suất vượt ngưỡng (>= 4 sự kiện trong 60 giây)
	if len(tracker.timestamps) >= 4 {
		// Mute container này trong 5 phút
		tracker.mutedUntil = now.Add(5 * time.Minute)
		tracker.timestamps = nil // Reset bộ đếm

		log.Printf("[THROTTLE] Phát hiện container %s bị crash loop / spam (>= 4 sự kiện/60s). Mute trong 5 phút.", container)

		// Gửi 1 thông báo cảnh báo duy nhất về Telegram
		go func() {
			message := fmt.Sprintf(
				"⚠️ *[DockerWhiz] CẢNH BÁO CRASH LOOP / SPAM*\n"+
					"------------------------------------\n"+
					"📦 *Container:* %s\n"+
					"🔄 *Hiện tượng:* Khởi động/dừng/sập liên tục (>= 4 lần trong 60 giây).\n"+
					"🔇 *Trạng thái:* Tạm dừng gửi thông báo cho container này trong *5 phút* để tránh spam Telegram.\n"+
					"ℹ️ *Ghi chú:* Mỗi khi phát sinh sự kiện mới trong lúc tắt tiếng, thời gian tắt tiếng sẽ tự động gia hạn thêm 5 phút để bảo vệ kênh Telegram.\n"+
					"------------------------------------\n"+
					"🛠️ *Đề xuất:* Hãy kiểm tra log của container bằng lệnh:\n`docker logs %s`",
				escapeMarkdown(container),
				escapeMarkdown(container),
			)
			sendTelegramRaw(message, token, chatID)
		}()

		return true
	}

	return false
}

func sendTelegramInfo(container, image, action string) {
	token, chatID := getTelegramCredentials()
	if token == "" || chatID == "" {
		log.Printf("[INFO] Container: %s | Image: %s | Action: %s (Telegram alerts disabled)", container, image, action)
		return
	}

	if shouldThrottleContainer(container, token, chatID) {
		return
	}


	timeStr := time.Now().Format("2006-01-02 15:04:05")
	var actionText string
	var statusEmoji string
	var footerText string
	if action == "start" {
		actionText = "ĐÃ KHỞI ĐỘNG / CHẠY LẠI"
		statusEmoji = "🟢"
		footerText = "👍 Container đang hoạt động bình thường."
	} else if action == "stop" {
		actionText = "ĐÃ DỪNG HOẠT ĐỘNG"
		statusEmoji = "🔴"
		footerText = "💤 Tiến trình liên quan đã dừng an toàn."
	} else {
		actionText = strings.ToUpper(action)
		statusEmoji = "ℹ️"
		footerText = "Trạng thái container đã cập nhật."
	}

	message := fmt.Sprintf(
		"ℹ️ *[DockerWhiz] THÔNG BÁO TRẠNG THÁI CONTAINER*\n"+
			"------------------------------------\n"+
			"📦 *Container:* %s\n"+
			"🖼️ *Image:* %s\n"+
			"🕒 *Thời gian:* %s\n"+
			"%s *Trạng thái:* %s thành công\n"+
			"------------------------------------\n"+
			"%s",
		escapeMarkdown(container),
		escapeMarkdown(image),
		escapeMarkdown(timeStr),
		statusEmoji,
		actionText,
		footerText,
	)

	sendTelegramRaw(message, token, chatID)
}

func sendTelegramAlert(container, image, reason string) {
	token, chatID := getTelegramCredentials()
	if token == "" || chatID == "" {
		log.Printf("[ALERT] Container: %s | Image: %s | Reason: %s (Telegram alerts disabled)", container, image, reason)
		return
	}

	if shouldThrottleContainer(container, token, chatID) {
		return
	}


	timeStr := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(
		"🚨 *[DockerWhiz] CẢNH BÁO CONTAINER SẬP*\n"+
			"------------------------------------\n"+
			"📦 *Container:* %s\n"+
			"🖼️ *Image:* %s\n"+
			"🕒 *Thời gian:* %s\n"+
			"❌ *Lỗi:* %s\n"+
			"------------------------------------\n"+
			"🛠️ *Hành động đề xuất:* Hãy SSH vào và kiểm tra dung lượng RAM bằng lệnh `free -m`.",
		escapeMarkdown(container),
		escapeMarkdown(image),
		escapeMarkdown(timeStr),
		escapeMarkdown(reason),
	)

	sendTelegramRaw(message, token, chatID)
}

func sendResourceAlertRaw(alertBody string) {
	token, chatID := getTelegramCredentials()
	if token == "" || chatID == "" {
		log.Printf("[RESOURCE ALERT] %s", alertBody)
		return
	}

	message := fmt.Sprintf(
		"⚠️ *[DockerWhiz] CẢNH BÁO TÀI NGUYÊN VPS*\n"+
			"------------------------------------\n"+
			"%s\n"+
			"------------------------------------\n"+
			"🛠️ *Hành động đề xuất:* Hãy kiểm tra lại các tiến trình hoặc cân nhắc nâng cấp gói VPS.",
		alertBody,
	)

	sendTelegramRaw(message, token, chatID)
}

func sendResourceRecovery(alertType, recoveryDetails string) {
	token, chatID := getTelegramCredentials()
	if token == "" || chatID == "" {
		log.Printf("[RESOURCE RECOVERY] %s - %s", alertType, recoveryDetails)
		return
	}

	message := fmt.Sprintf(
		"✅ *[DockerWhiz] HỆ THỐNG ĐÃ HẠ NHIỆT*\n"+
			"------------------------------------\n"+
			"❇️ *Cảnh báo đã tắt:* %s\n"+
			"ℹ️ *Chi tiết:* %s\n"+
			"------------------------------------\n"+
			"👍 Mọi thứ đã trở lại hoạt động bình thường.",
		alertType, recoveryDetails,
	)

	sendTelegramRaw(message, token, chatID)
}

func sendTelegramRaw(message, token, chatID string) {
	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       message,
		"parse_mode": "Markdown",
	}

	jsonPayload, _ := json.Marshal(payload)
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		log.Printf("Failed to send Telegram message: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Telegram API error: %d - %s", resp.StatusCode, string(body))
	}
}

type telegramUpdate struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		MessageID int64 `json:"message_id"`
		Chat      *struct {
			ID int64 `json:"id"`
		} `json:"chat"`
		From *struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
		} `json:"from"`
		Text string `json:"text"`
	} `json:"message"`
}

type telegramUpdatesResp struct {
	OK     bool             `json:"ok"`
	Result []telegramUpdate `json:"result"`
}

func performDockerAction(ctx context.Context, id, action string) error {
	apiURL := fmt.Sprintf("http://localhost/containers/%s/%s", id, action)
	if action == "stop" {
		apiURL += "?t=10"
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, nil)
	if err != nil {
		return err
	}

	resp, err := dockerClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		var dockerError struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(body, &dockerError); err == nil && dockerError.Message != "" {
			return fmt.Errorf(dockerError.Message)
		}
		return fmt.Errorf("Docker returned status %d: %s", resp.StatusCode, string(body))
	}

	triggerUpdate()
	return nil
}

func handleTelegramCommand(text, token, chatID string) {
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, "/") {
		return
	}

	parts := strings.Fields(text)
	cmd := parts[0]

	switch cmd {
	case "/help", "/start":
		helpMsg := "💡 *[DockerWhiz] DANH SÁCH LỆNH ĐIỀU KHIỂN*\n" +
			"------------------------------------\n" +
			"📌 `/status` hoặc `/list` - Xem nhanh tài nguyên VPS & danh sách containers\n" +
			"🧹 `/prune` - Dọn dẹp tài nguyên Docker dư thừa (Smart Prune)\n" +
			"🔄 `/restart <name_or_id>` - Khởi động lại một container\n" +
			"🟢 `/start_container <name_or_id>` - Khởi động một container đang dừng\n" +
			"🔴 `/stop_container <name_or_id>` - Dừng một container đang chạy\n" +
			"💡 `/help` - Hiển thị hướng dẫn này"
		sendTelegramRaw(helpMsg, token, chatID)

	case "/status", "/list":
		state, err := getSystemState()
		if err != nil {
			sendTelegramRaw(fmt.Sprintf("❌ Lỗi khi lấy thông tin hệ thống: %v", err), token, chatID)
			return
		}

		// Format host resources
		hostInfo := fmt.Sprintf(
			"🖥️ *THÔNG SỐ VPS:*\n"+
				"• *CPU:* %.1f%%\n"+
				"• *RAM:* %.1f%% (%.2fGB / %.1fGB)\n"+
				"• *Disk:* %.1f%% (%.1fGB / %.0fGB)\n\n",
			state.Host.CPUUsage,
			state.Host.RAMPercent, state.Host.RAMUsed, state.Host.RAMTotal,
			state.Host.DiskPercent, state.Host.DiskUsed, state.Host.DiskTotal,
		)

		// Format container list
		var runningList []string
		var stoppedList []string

		for _, c := range state.Containers {
			ramStr := ""
			if c.State == "running" {
				ramStr = fmt.Sprintf(" (RAM: %.1fMB)", c.RAMUsed)
				runningList = append(runningList, fmt.Sprintf("🟢 *%s*%s", escapeMarkdown(c.Name), ramStr))
			} else {
				stoppedList = append(stoppedList, fmt.Sprintf("🔴 *%s* (%s)", escapeMarkdown(c.Name), escapeMarkdown(c.Status)))
			}
		}

		containerInfo := fmt.Sprintf(
			"📦 *TRẠNG THÁI CONTAINERS (%d đang chạy / %d tổng):*\n",
			state.RunningCount, state.TotalContainers,
		)

		if len(runningList) > 0 {
			containerInfo += strings.Join(runningList, "\n") + "\n"
		}
		if len(stoppedList) > 0 {
			containerInfo += strings.Join(stoppedList, "\n") + "\n"
		}
		if len(runningList) == 0 && len(stoppedList) == 0 {
			containerInfo += "_Không có container nào._\n"
		}

		sendTelegramRaw(hostInfo+containerInfo, token, chatID)

	case "/prune":
		sendTelegramRaw("🧹 Đang thực hiện dọn dẹp Docker, vui lòng đợi...", token, chatID)
		result, err := runDockerPrune()
		if err != nil {
			sendTelegramRaw(fmt.Sprintf("❌ Dọn dẹp thất bại: %v", err), token, chatID)
			return
		}

		spaceStr := formatBytesHuman(int64(result.SpaceReclaimed))
		summary := fmt.Sprintf(
			"✅ *Dọn dẹp Docker thành công!*\n"+
				"• Giải phóng: *%s*\n"+
				"• Containers đã xóa: %d\n"+
				"• Images đã xóa: %d\n"+
				"• Networks đã xóa: %d\n"+
				"• Volumes đã xóa: %d",
			spaceStr,
			len(result.ContainersDeleted),
			len(result.ImagesDeleted),
			len(result.NetworksDeleted),
			len(result.VolumesDeleted),
		)
		sendTelegramRaw(summary, token, chatID)

	case "/restart", "/start_container", "/stop_container":
		if len(parts) < 2 {
			sendTelegramRaw(fmt.Sprintf("⚠️ Vui lòng nhập tên hoặc ID container. Ví dụ: `%s my-container`", cmd), token, chatID)
			return
		}
		target := parts[1]
		action := "restart"
		actionName := "Khởi động lại"
		if cmd == "/start_container" {
			action = "start"
			actionName = "Bắt đầu"
		} else if cmd == "/stop_container" {
			action = "stop"
			actionName = "Dừng"
		}

		sendTelegramRaw(fmt.Sprintf("⚙️ Đang thực hiện `%s` cho container `%s`...", actionName, target), token, chatID)

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		err := performDockerAction(ctx, target, action)
		if err != nil {
			sendTelegramRaw(fmt.Sprintf("❌ Thao tác thất bại: %v", err), token, chatID)
			return
		}

		sendTelegramRaw(fmt.Sprintf("✅ Thao tác `%s` thành công cho container `%s`!", actionName, target), token, chatID)

	default:
		sendTelegramRaw("❓ Lệnh không hợp lệ. Gửi `/help` để xem danh sách lệnh.", token, chatID)
	}
}

func listenTelegramCommands() {
	var offset int64 = 0
	client := &http.Client{Timeout: 40 * time.Second}

	log.Println("Telegram command listener started...")

	for {
		token, chatID := getTelegramCredentials()
		if token == "" || chatID == "" {
			time.Sleep(10 * time.Second)
			continue
		}

		apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?timeout=30", token)
		if offset > 0 {
			apiURL = fmt.Sprintf("%s&offset=%d", apiURL, offset)
		}

		resp, err := client.Get(apiURL)
		if err != nil {
			time.Sleep(10 * time.Second)
			continue
		}

		var updateResp telegramUpdatesResp
		if err := json.NewDecoder(resp.Body).Decode(&updateResp); err != nil {
			resp.Body.Close()
			time.Sleep(10 * time.Second)
			continue
		}
		resp.Body.Close()

		if !updateResp.OK {
			time.Sleep(10 * time.Second)
			continue
		}

		for _, update := range updateResp.Result {
			if update.UpdateID >= offset {
				offset = update.UpdateID + 1
			}

			if update.Message == nil || update.Message.Chat == nil {
				continue
			}

			msgChatIDStr := fmt.Sprintf("%d", update.Message.Chat.ID)
			if msgChatIDStr != chatID {
				log.Printf("[TELEGRAM] Blocked unauthorized message from chat ID: %s", msgChatIDStr)
				continue
			}

			// Security: Check Telegram Admin ID if configured
			if appConfig.TelegramAdminID != "" {
				if update.Message.From == nil {
					log.Println("[TELEGRAM] Blocked message: missing sender details")
					continue
				}
				senderIDStr := fmt.Sprintf("%d", update.Message.From.ID)
				if senderIDStr != appConfig.TelegramAdminID {
					log.Printf("[TELEGRAM] Blocked command from unauthorized user: %s (ID: %s)", update.Message.From.Username, senderIDStr)
					continue
				}
			}

			handleTelegramCommand(update.Message.Text, token, chatID)
		}

		time.Sleep(500 * time.Millisecond)
	}
}

func listenDockerEvents() {
	eventsClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", config.DockerSocket)
			},
		},
		Timeout: 0,
	}

	for {
		log.Println("Connecting to Docker events socket...")
		resp, err := eventsClient.Get("http://localhost/events?filters=%7B%22type%22%3A%7B%22container%22%3Atrue%7D%7D")
		if err != nil {
			log.Printf("Docker events connection error: %v, retrying in 5 seconds...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		reader := bufio.NewReader(resp.Body)
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				resp.Body.Close()
				log.Printf("Docker events connection disconnected: %v, reconnecting...", err)
				break
			}

			var event DockerEvent
			if err := json.Unmarshal(line, &event); err != nil {
				continue
			}

			triggerUpdate()

			if event.Type == "container" {
				action := event.Action
				isAlert := false
				reason := ""

				if action == "oom" {
					isAlert = true
					reason = "Out Of Memory (OOM)"
				} else if action == "die" {
					exitCode := event.Actor.Attributes["exitCode"]
					if exitCode != "0" {
						isAlert = true
						if exitCode == "137" {
							reason = "OOM Killed (Exit Code 137)"
						} else {
							reason = fmt.Sprintf("Bị sập với Exit Code %s", exitCode)
						}
					}
				} else if strings.Contains(action, "health_status") && strings.Contains(action, "unhealthy") {
					isAlert = true
					reason = "Không vượt qua kiểm tra sức khỏe (Unhealthy)"
				} else if action == "start" {
					containerName := event.Actor.Attributes["name"]
					imageName := event.Actor.Attributes["image"]
					go sendTelegramInfo(containerName, imageName, "start")
				} else if action == "stop" {
					containerName := event.Actor.Attributes["name"]
					imageName := event.Actor.Attributes["image"]
					go sendTelegramInfo(containerName, imageName, "stop")
				}

				if isAlert {
					containerName := event.Actor.Attributes["name"]
					imageName := event.Actor.Attributes["image"]
					go sendTelegramAlert(containerName, imageName, reason)
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
}

// System Resource Monitor Loop
func getHeaviestRAMContainer() string {
	state, err := getSystemState()
	if err != nil || len(state.Containers) == 0 {
		return ""
	}

	var heaviest ContainerUI
	found := false
	for _, c := range state.Containers {
		if c.State == "running" {
			if !found || c.RAMUsed > heaviest.RAMUsed {
				heaviest = c
				found = true
			}
		}
	}

	if found && heaviest.RAMUsed > 0 {
		return fmt.Sprintf("%s (%.0fMB)", heaviest.Name, heaviest.RAMUsed)
	}
	return ""
}

func sysmonLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	log.Println("System Resource Monitor started (60s loop)...")

	// Trigger immediately on startup
	time.Sleep(5 * time.Second) // wait for init client

	for {
		// 1. CPU Monitor
		cpuUsage, err := getCPUUsage() // sleeps 500ms
		if err == nil {
			if cpuUsage > 90.0 {
				cpuOverLimitCount++
				if cpuOverLimitCount >= 2 {
					if !cpuAlertActive {
						cpuAlertActive = true
						go sendResourceAlertRaw(fmt.Sprintf(
							"🚨 *Loại cảnh báo:* QUÁ TẢI CPU\n"+
								"📊 *Trạng thái hiện tại:* %.1f%% đã dùng\n"+
								"ℹ️ *Chi tiết:* CPU liên tục hoạt động trên 90%% qua 2 lần quét.",
							cpuUsage,
						))
					}
				}
			} else {
				cpuOverLimitCount = 0
				if cpuAlertActive {
					cpuAlertActive = false
					go sendResourceRecovery("QUÁ TẢI CPU", "CPU đã hạ nhiệt và hoạt động bình thường trở lại.")
				}
			}
		}

		// 2. RAM Monitor
		ramTotal, ramAvailable, err := getMemoryUsage()
		if err == nil && ramTotal > 0 {
			ramUsed := ramTotal - ramAvailable
			ramUsedPercent := (float64(ramUsed) / float64(ramTotal)) * 100.0
			ramFreePercent := (float64(ramAvailable) / float64(ramTotal)) * 100.0

			if ramFreePercent < 10.0 {
				if !ramAlertActive {
					ramAlertActive = true
					heaviest := getHeaviestRAMContainer()
					var heaviestText string
					if heaviest != "" {
						heaviestText = fmt.Sprintf("\nℹ️ *Container ngốn nhiều RAM nhất hiện tại:* %s", heaviest)
					}

					freeMB := float64(ramAvailable) / (1024 * 1024)
					go sendResourceAlertRaw(fmt.Sprintf(
						"🚨 *Loại cảnh báo:* HẾT BỘ NHỚ RAM\n"+
							"📊 *Trạng thái hiện tại:* %.1f%% đã dùng\n"+
							"📈 *RAM trống còn lại:* ~%.0f MB%s",
						ramUsedPercent, freeMB, heaviestText,
					))
				}
			} else {
				if ramAlertActive {
					ramAlertActive = false
					go sendResourceRecovery("HẾT BỘ NHỚ RAM", "Dung lượng RAM trống đã vượt trên 10%.")
				}
			}
		}

		// 3. Disk Monitor
		diskTotal, diskFree, err := getDiskUsage(diskPath)
		if err == nil && diskTotal > 0 {
			diskUsed := diskTotal - diskFree
			diskUsedPercent := (float64(diskUsed) / float64(diskTotal)) * 100.0

			if diskUsedPercent > 85.0 {
				if !diskAlertActive {
					diskAlertActive = true
					freeGB := float64(diskFree) / (1024 * 1024 * 1024)
					go sendResourceAlertRaw(fmt.Sprintf(
						"🚨 *Loại cảnh báo:* HẾT DUNG LƯỢNG ĐĨA\n"+
							"📊 *Trạng thái hiện tại:* %.1f%% đã dùng\n"+
							"📈 *Dung lượng đĩa trống:* ~%.1f GB",
						diskUsedPercent, freeGB,
					))
				}
			} else {
				if diskAlertActive {
					diskAlertActive = false
					go sendResourceRecovery("HẾT DUNG LƯỢNG ĐĨA", "Dung lượng đĩa trống đã trở lại ngưỡng an toàn (>15%).")
				}
			}
		}

		select {
		case <-ticker.C:
		}
	}
}

// humanDuration formats a duration into a human-readable Vietnamese string
func humanDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d giây", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d phút", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		hours := int(d.Hours())
		return fmt.Sprintf("%d giờ", hours)
	}
	days := int(d.Hours() / 24)
	return fmt.Sprintf("%d ngày", days)
}

// formatBytes formats bytes into human-readable string
func formatBytesHuman(b int64) string {
	if b < 0 {
		return "Không rõ"
	}
	if b == 0 {
		return "0 B"
	}
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB"}
	return fmt.Sprintf("%.1f %s", float64(b)/float64(div), units[exp])
}

// buildPruneFilter builds the "until" filter query param for Docker prune APIs
func buildPruneFilter(keepRecentHours int) string {
	if keepRecentHours <= 0 {
		return ""
	}
	// Docker accepts filter like: filters={"until":["24h"]}
	filterJSON := fmt.Sprintf(`{"until":["%dh"]}`, keepRecentHours)
	return "filters=" + filterJSON
}

// getPrunePreview fetches lists of resources that WOULD be pruned
func getPrunePreview() (PrunePreview, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	preview := PrunePreview{
		Containers: []PrunePreviewItem{},
		Images:     []PrunePreviewItem{},
		Networks:   []PrunePreviewItem{},
		Volumes:    []PrunePreviewItem{},
	}

	now := time.Now()
	keepHours := appConfig.Prune.KeepRecentHours
	var cutoff time.Time
	if keepHours > 0 {
		cutoff = now.Add(-time.Duration(keepHours) * time.Hour)
	}

	// 1. Stopped containers
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://localhost/containers/json?all=1&filters={\"status\":[\"exited\",\"dead\",\"created\"]}", nil)
	if resp, err := dockerClient.Do(req); err == nil {
		defer resp.Body.Close()
		var containers []struct {
			ID      string   `json:"Id"`
			Names   []string `json:"Names"`
			Image   string   `json:"Image"`
			State   string   `json:"State"`
			Status  string   `json:"Status"`
			Created int64    `json:"Created"`
			SizeRw  int64    `json:"SizeRw"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&containers); err == nil {
			for _, c := range containers {
				created := time.Unix(c.Created, 0)
				if keepHours > 0 && created.After(cutoff) {
					continue // Keep recent
				}
				name := c.Image
				if len(c.Names) > 0 {
					name = strings.TrimPrefix(c.Names[0], "/")
				}
				preview.Containers = append(preview.Containers, PrunePreviewItem{
					ID:    c.ID[:12],
					Name:  name,
					Type:  "container",
					Size:  c.SizeRw,
					Age:   humanDuration(now.Sub(created)),
					Extra: c.Status,
				})
			}
		}
	}

	// 2. Dangling / unused images
	danglingFilter := "1" // Only dangling by default
	if !appConfig.Prune.DanglingOnly {
		danglingFilter = "0"
	}
	imgURL := fmt.Sprintf("http://localhost/images/json?filters={\"dangling\":[\"%s\"]}", danglingFilter)
	req, _ = http.NewRequestWithContext(ctx, "GET", imgURL, nil)
	if resp, err := dockerClient.Do(req); err == nil {
		defer resp.Body.Close()
		var images []struct {
			ID       string   `json:"Id"`
			RepoTags []string `json:"RepoTags"`
			Size     int64    `json:"Size"`
			Created  int64    `json:"Created"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&images); err == nil {
			for _, img := range images {
				created := time.Unix(img.Created, 0)
				if keepHours > 0 && created.After(cutoff) {
					continue
				}
				name := "<none>:<none>"
				if len(img.RepoTags) > 0 && img.RepoTags[0] != "<none>:<none>" {
					name = img.RepoTags[0]
				}
				preview.Images = append(preview.Images, PrunePreviewItem{
					ID:    img.ID[7:19], // Remove "sha256:" prefix, take 12 chars
					Name:  name,
					Type:  "image",
					Size:  img.Size,
					Age:   humanDuration(now.Sub(created)),
					Extra: fmt.Sprintf("%.1f MB", float64(img.Size)/(1024*1024)),
				})
				preview.EstimatedSpace += img.Size
			}
		}
	}

	// 3. Unused networks (exclude default ones)
	req, _ = http.NewRequestWithContext(ctx, "GET", "http://localhost/networks", nil)
	if resp, err := dockerClient.Do(req); err == nil {
		defer resp.Body.Close()
		var networks []struct {
			ID         string                 `json:"Id"`
			Name       string                 `json:"Name"`
			Driver     string                 `json:"Driver"`
			Scope      string                 `json:"Scope"`
			Created    string                 `json:"Created"`
			Containers map[string]interface{} `json:"Containers"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&networks); err == nil {
			defaultNets := map[string]bool{"bridge": true, "host": true, "none": true}
			for _, net := range networks {
				if defaultNets[net.Name] {
					continue
				}
				if len(net.Containers) > 0 {
					continue // In use
				}
				preview.Networks = append(preview.Networks, PrunePreviewItem{
					ID:    net.ID[:12],
					Name:  net.Name,
					Type:  "network",
					Size:  -1,
					Age:   "",
					Extra: net.Driver,
				})
			}
		}
	}

	// 4. Unused volumes
	req, _ = http.NewRequestWithContext(ctx, "GET", "http://localhost/volumes?filters={\"dangling\":[\"true\"]}", nil)
	if resp, err := dockerClient.Do(req); err == nil {
		defer resp.Body.Close()
		var volResp struct {
			Volumes []struct {
				Name      string `json:"Name"`
				Driver    string `json:"Driver"`
				CreatedAt string `json:"CreatedAt"`
				UsageData *struct {
					Size     int64 `json:"Size"`
					RefCount int64 `json:"RefCount"`
				} `json:"UsageData,omitempty"`
			} `json:"Volumes"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&volResp); err == nil {
			for _, vol := range volResp.Volumes {
				size := int64(-1)
				if vol.UsageData != nil {
					size = vol.UsageData.Size
					preview.EstimatedSpace += size
				}
				preview.Volumes = append(preview.Volumes, PrunePreviewItem{
					ID:    vol.Name[:min(12, len(vol.Name))],
					Name:  vol.Name,
					Type:  "volume",
					Size:  size,
					Age:   "",
					Extra: vol.Driver,
				})
			}
		}
	}

	preview.TotalItems = len(preview.Containers) + len(preview.Images) + len(preview.Networks) + len(preview.Volumes)
	return preview, nil
}

func runDockerPrune() (*PruneResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cfg := appConfig.Prune
	result := &PruneResult{
		ContainersDeleted: []string{},
		ImagesDeleted:     []string{},
		NetworksDeleted:   []string{},
		VolumesDeleted:    []string{},
	}

	filterQuery := buildPruneFilter(cfg.KeepRecentHours)

	// 1. Prune containers
	if cfg.PruneContainers {
		url := "http://localhost/containers/prune"
		if filterQuery != "" {
			url += "?" + filterQuery
		}
		req, _ := http.NewRequestWithContext(ctx, "POST", url, nil)
		if resp, err := dockerClient.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var pr dockerPruneContainersResp
				if err := json.NewDecoder(resp.Body).Decode(&pr); err == nil {
					result.ContainersDeleted = pr.ContainersDeleted
					result.SpaceReclaimed += pr.SpaceReclaimed
				}
			}
		}
	}

	// 2. Prune networks
	if cfg.PruneNetworks {
		url := "http://localhost/networks/prune"
		if filterQuery != "" {
			url += "?" + filterQuery
		}
		req, _ := http.NewRequestWithContext(ctx, "POST", url, nil)
		if resp, err := dockerClient.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var pr dockerPruneNetworksResp
				if err := json.NewDecoder(resp.Body).Decode(&pr); err == nil {
					result.NetworksDeleted = pr.NetworksDeleted
				}
			}
		}
	}

	// 3. Prune volumes (only if explicitly enabled — dangerous!)
	if cfg.PruneVolumes {
		req, _ := http.NewRequestWithContext(ctx, "POST", "http://localhost/volumes/prune", nil)
		if resp, err := dockerClient.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var pr dockerPruneVolumesResp
				if err := json.NewDecoder(resp.Body).Decode(&pr); err == nil {
					result.VolumesDeleted = pr.VolumesDeleted
					result.SpaceReclaimed += pr.SpaceReclaimed
				}
			}
		}
	}

	// 4. Prune images
	if cfg.PruneImages {
		danglingParam := "1" // true = only dangling
		if !cfg.DanglingOnly {
			danglingParam = "0"
		}
		url := fmt.Sprintf("http://localhost/images/prune?filters={\"dangling\":[\"%s\"]}", danglingParam)
		if cfg.KeepRecentHours > 0 {
			url = fmt.Sprintf("http://localhost/images/prune?filters={\"dangling\":[\"%s\"],\"until\":[\"%dh\"]}", danglingParam, cfg.KeepRecentHours)
		}
		req, _ := http.NewRequestWithContext(ctx, "POST", url, nil)
		if resp, err := dockerClient.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var pr dockerPruneImagesResp
				if err := json.NewDecoder(resp.Body).Decode(&pr); err == nil {
					for _, img := range pr.ImagesDeleted {
						if img.Deleted != "" {
							result.ImagesDeleted = append(result.ImagesDeleted, img.Deleted)
						} else if img.Untagged != "" {
							result.ImagesDeleted = append(result.ImagesDeleted, img.Untagged)
						}
					}
					result.SpaceReclaimed += pr.SpaceReclaimed
				}
			}
		}
	}

	// Update last prune time
	appConfig.Prune.LastPruneTime = time.Now().Unix()
	_ = saveConfig()

	// Trigger SSE update
	triggerUpdate()

	// Send detailed Telegram notification
	token, chatID := getTelegramCredentials()
	if token != "" && chatID != "" {
		totalDeleted := len(result.ContainersDeleted) + len(result.ImagesDeleted) +
			len(result.NetworksDeleted) + len(result.VolumesDeleted)
		spaceStr := formatBytesHuman(int64(result.SpaceReclaimed))

		var details []string
		if len(result.ContainersDeleted) > 0 {
			details = append(details, fmt.Sprintf("📦 Containers: %d đã xóa", len(result.ContainersDeleted)))
		}
		if len(result.ImagesDeleted) > 0 {
			details = append(details, fmt.Sprintf("🖼️ Images: %d đã xóa", len(result.ImagesDeleted)))
		}
		if len(result.NetworksDeleted) > 0 {
			details = append(details, fmt.Sprintf("🌐 Networks: %d đã xóa", len(result.NetworksDeleted)))
		}
		if len(result.VolumesDeleted) > 0 {
			details = append(details, fmt.Sprintf("💿 Volumes: %d đã xóa", len(result.VolumesDeleted)))
		}

		detailStr := "Không có gì để dọn."
		if len(details) > 0 {
			detailStr = strings.Join(details, "\n")
		}

		message := fmt.Sprintf(
			"🧹 *[DockerWhiz] HOÀN THÀNH DỌN RÁC DOCKER*\n"+
				"------------------------------------\n"+
				"%s\n"+
				"------------------------------------\n"+
				"📊 Tổng: %d items đã xóa\n"+
				"💾 Dung lượng giải phóng: *%s*\n"+
				"🕒 Thời gian: %s",
			detailStr,
			totalDeleted,
			spaceStr,
			time.Now().Format("2006-01-02 15:04:05"),
		)
		sendTelegramRaw(message, token, chatID)
	}

	return result, nil
}

func sysPruneLoop() {
	ticker := time.NewTicker(10 * time.Minute) // Check every 10 minutes
	defer ticker.Stop()

	log.Println("System Docker Prune Monitor started (10m loop)...")

	for {
		select {
		case <-ticker.C:
			if !appConfig.Prune.Enabled {
				continue
			}
			if appConfig.Prune.IntervalHours <= 0 {
				continue
			}
			now := time.Now().Unix()
			diffSeconds := now - appConfig.Prune.LastPruneTime
			intervalSeconds := int64(appConfig.Prune.IntervalHours * 3600)
			if diffSeconds >= intervalSeconds {
				log.Println("[PRUNE] Triggering scheduled Docker smart prune...")
				runDockerPrune()
			}
		}
	}
}

func triggerUpdate() {
	select {
	case updateTriggerChan <- struct{}{}:
	default:
		// Queue full
	}
}

func sseBroadcastLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			broadcastState()
		case <-updateTriggerChan:
			time.Sleep(300 * time.Millisecond) // debounce
			drainTriggerChan()
			broadcastState()
		}
	}
}

func drainTriggerChan() {
	for {
		select {
		case <-updateTriggerChan:
		default:
			return
		}
	}
}

func broadcastState() {
	state, err := getSystemState()
	if err != nil {
		log.Printf("Error getting Docker status for broadcast: %v", err)
		return
	}

	data, err := json.Marshal(state)
	if err != nil {
		return
	}

	sseManager.mu.Lock()
	defer sseManager.mu.Unlock()
	for clientChan := range sseManager.clients {
		select {
		case clientChan <- string(data):
		default:
			// Skip slow client
		}
	}
}

func (m *SSEManager) handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	clientChan := make(chan string, 5)

	m.mu.Lock()
	m.clients[clientChan] = true
	m.mu.Unlock()

	log.Printf("New client connected to SSE. Total clients: %d", len(m.clients))

	// Send initial state immediately
	state, err := getSystemState()
	if err == nil {
		data, _ := json.Marshal(state)
		fmt.Fprintf(w, "data: %s\n\n", string(data))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}

	defer func() {
		m.mu.Lock()
		delete(m.clients, clientChan)
		m.mu.Unlock()
		close(clientChan)
		log.Printf("Client disconnected from SSE. Total clients: %d", len(m.clients))
	}()

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case msg, ok := <-clientChan:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", msg)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
	}
}

func containerActionHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/containers/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request path",
		})
		return
	}

	containerID := parts[0]
	action := parts[1]

	if action == "logs" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "Method Not Allowed",
			})
			return
		}
		handleGetLogs(w, r, containerID)
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Method Not Allowed",
		})
		return
	}

	if action != "start" && action != "stop" && action != "restart" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Unknown action",
		})
		return
	}

	handleContainerAction(w, r, containerID, action)
}

func handleContainerAction(w http.ResponseWriter, r *http.Request, id, action string) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	err := performDockerAction(ctx, id, action)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func handleGetLogs(w http.ResponseWriter, r *http.Request, id string) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	apiURL := fmt.Sprintf("http://localhost/containers/%s/logs?stdout=1&stderr=1&tail=100", id)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to create request: %v", err),
		})
		return
	}

	resp, err := dockerClient.Do(req)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Docker socket communication failure: %v", err),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		var dockerError struct {
			Message string `json:"message"`
		}
		errorMsg := string(body)
		if err := json.Unmarshal(body, &dockerError); err == nil && dockerError.Message != "" {
			errorMsg = dockerError.Message
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   errorMsg,
		})
		return
	}

	var out bytes.Buffer
	header := make([]byte, 8)
	for {
		_, err := io.ReadFull(resp.Body, header)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			break
		}

		size := uint32(header[4])<<24 | uint32(header[5])<<16 | uint32(header[6])<<8 | uint32(header[7])
		if size == 0 {
			continue
		}

		frame := make([]byte, size)
		_, err = io.ReadFull(resp.Body, frame)
		if err != nil {
			out.Write(frame)
			break
		}
		out.Write(frame)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"logs":    out.String(),
	})
}

func settingsGetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, `{"error":"Method Not Allowed","success":false}`, http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":          true,
		"telegramBotToken": appConfig.TelegramBotToken,
		"telegramChatID":   appConfig.TelegramChatID,
		"telegramDisabled": appConfig.TelegramDisabled,
		"telegramAdminID":  appConfig.TelegramAdminID,
		"prune":            appConfig.Prune,
	})
}

func settingsSaveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, `{"error":"Method Not Allowed","success":false}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		TelegramBotToken string      `json:"telegramBotToken"`
		TelegramChatID   string      `json:"telegramChatID"`
		TelegramDisabled bool        `json:"telegramDisabled"`
		TelegramAdminID  string      `json:"telegramAdminID"`
		Prune            PruneConfig `json:"prune"`
	}

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024*1024)).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid JSON request body",
		})
		return
	}

	appConfig.TelegramBotToken = strings.TrimSpace(req.TelegramBotToken)
	appConfig.TelegramChatID = strings.TrimSpace(req.TelegramChatID)
	appConfig.TelegramDisabled = req.TelegramDisabled
	appConfig.TelegramAdminID = strings.TrimSpace(req.TelegramAdminID)
	// Preserve LastPruneTime — frontend should not overwrite it
	req.Prune.LastPruneTime = appConfig.Prune.LastPruneTime
	appConfig.Prune = req.Prune

	if err := saveConfig(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to save config: %v", err),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func settingsTestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, `{"error":"Method Not Allowed","success":false}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		TelegramBotToken string `json:"telegramBotToken"`
		TelegramChatID   string `json:"telegramChatID"`
	}

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024*1024)).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid JSON request body",
		})
		return
	}

	token := strings.TrimSpace(req.TelegramBotToken)
	chatID := strings.TrimSpace(req.TelegramChatID)

	if token == "" || chatID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Bot Token and Chat ID cannot be empty",
		})
		return
	}

	timeStr := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(
		"✨ *[DockerWhiz] KIỂM TRA KẾT NỐI TELEGRAM*\n"+
			"------------------------------------\n"+
			"✅ Kết nối thành công tới Telegram Bot!\n"+
			"🕒 Thời gian gửi: %s\n"+
			"------------------------------------\n"+
			"👍 Cấu hình của bạn đã sẵn sàng để hoạt động.",
		timeStr,
	)

	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       message,
		"parse_mode": "Markdown",
	}

	jsonPayload, _ := json.Marshal(payload)
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to communicate with Telegram: %v", err),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var apiError struct {
			Description string `json:"description"`
		}
		errorMsg := fmt.Sprintf("Telegram HTTP %d", resp.StatusCode)
		if err := json.Unmarshal(body, &apiError); err == nil && apiError.Description != "" {
			errorMsg = apiError.Description
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   errorMsg,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func settingsPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, `{"error":"Method Not Allowed","success":false}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024*1024)).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid JSON request body",
		})
		return
	}

	oldPassword := req.OldPassword
	newPassword := req.NewPassword

	if oldPassword == "" || newPassword == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Passwords cannot be empty",
		})
		return
	}

	expectedHash := hashPassword(oldPassword, appConfig.Salt)
	// Secure constant-time comparison
	if subtle.ConstantTimeCompare([]byte(expectedHash), []byte(appConfig.PasswordHash)) != 1 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Mật khẩu hiện tại không chính xác",
		})
		return
	}

	newSalt, err := generateSalt()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Failed to generate salt",
		})
		return
	}
	newHash := hashPassword(newPassword, newSalt)

	appConfig.PasswordHash = newHash
	appConfig.Salt = newSalt

	if err := saveConfig(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to save config: %v", err),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func prunePreviewHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, `{"error":"Method Not Allowed","success":false}`, http.StatusMethodNotAllowed)
		return
	}

	preview, err := getPrunePreview()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"preview": preview,
	})
}

func settingsPruneHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, `{"error":"Method Not Allowed","success":false}`, http.StatusMethodNotAllowed)
		return
	}

	result, err := runDockerPrune()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"result":  result,
	})
}

func settingsToggleTelegramHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, `{"error":"Method Not Allowed","success":false}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Disabled bool `json:"disabled"`
	}

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024*1024)).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid JSON request body",
		})
		return
	}

	appConfig.TelegramDisabled = req.Disabled

	if err := saveConfig(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to save config: %v", err),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":          true,
		"telegramDisabled": appConfig.TelegramDisabled,
	})
}

func main() {
	config.DockerSocket = getEnv("DOCKER_SOCKET", "/var/run/docker.sock")
	config.Host = getEnv("HOST", "0.0.0.0")
	config.Port = getEnv("PORT", "8082")
	config.TelegramBotToken = os.Getenv("TELEGRAM_BOT_TOKEN")
	config.TelegramChatID = os.Getenv("TELEGRAM_CHAT_ID")
	diskPath = getEnv("DISK_PATH", "/")

	log.Println("--- DockerWhiz Starting ---")
	log.Printf("Docker Socket Path: %s", config.DockerSocket)
	log.Printf("Listening Address: %s:%s", config.Host, config.Port)
	log.Printf("Disk Path to Monitor: %s", diskPath)

	if config.TelegramBotToken != "" && config.TelegramChatID != "" {
		log.Println("Telegram Alerting: ENABLED")
	} else {
		log.Println("Telegram Alerting: DISABLED (missing configs)")
	}

	// Read or initialize appConfig
	loadConfig()

	// If no password is configured, start Setup Mode and generate token
	if appConfig.PasswordHash == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err == nil {
			setupToken = hex.EncodeToString(b)
			log.Println("==================================================")
			log.Println("🚨 [SECURITY] NANO DOCK SETUP MODE IS ACTIVE 🚨")
			log.Println("Please use the following Setup Token to configure DockerWhiz:")
			log.Printf("👉   %s   👈", setupToken)
			log.Println("==================================================")
		} else {
			log.Fatalf("Failed to generate secure Setup Token: %v", err)
		}
	}

	// Verify socket path exists
	if _, err := os.Stat(config.DockerSocket); os.IsNotExist(err) {
		log.Printf("[WARNING] Docker Socket not found at %s. Ensure it is mapped properly.", config.DockerSocket)
	}

	initDockerClient()

	go listenDockerEvents()
	go sseBroadcastLoop()
	go sysmonLoop()   // Start resource monitoring
	go sysPruneLoop() // Start scheduled prune monitoring
	go listenTelegramCommands()

	// Authentication API endpoints
	http.HandleFunc("/api/auth/status", authStatusHandler)
	http.HandleFunc("/api/auth/setup", authSetupHandler)
	http.HandleFunc("/api/auth/login", authLoginHandler)
	http.HandleFunc("/api/auth/logout", authLogoutHandler)

	// Protected API endpoints
	http.HandleFunc("/api/stream", requireAuth(sseManager.handler))
	http.HandleFunc("/api/containers/", requireAuth(containerActionHandler))
	http.HandleFunc("/api/settings/get", requireAuth(settingsGetHandler))
	http.HandleFunc("/api/settings", requireAuth(settingsSaveHandler))
	http.HandleFunc("/api/settings/test", requireAuth(settingsTestHandler))
	http.HandleFunc("/api/settings/password", requireAuth(settingsPasswordHandler))
	http.HandleFunc("/api/settings/prune/preview", requireAuth(prunePreviewHandler))
	http.HandleFunc("/api/settings/prune", requireAuth(settingsPruneHandler))
	http.HandleFunc("/api/settings/telegram/toggle", requireAuth(settingsToggleTelegramHandler))

	// Serve UI
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := embedFS.ReadFile("index.html")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	bindAddr := net.JoinHostPort(config.Host, config.Port)
	log.Printf("DockerWhiz server listening on %s", bindAddr)
	if err := http.ListenAndServe(bindAddr, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
