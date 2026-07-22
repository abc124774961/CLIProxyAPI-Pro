package management

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	codexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const maxAgentIdentityRegistrationBatch = 2000

type agentIdentityRegistrationRuntime interface {
	RegistrationStatus() codexauth.AgentIdentityRegistrationStatus
	SetRegistrationClient(*http.Client)
	RetryTaskRegistration() (codexauth.AgentIdentityRegistrationStatus, bool)
}

type agentIdentityRegistrationResult struct {
	Name         string                                    `json:"name"`
	Queued       bool                                      `json:"queued"`
	Registration codexauth.AgentIdentityRegistrationStatus `json:"registration"`
}

// ListAgentIdentityRegistrations returns only registration progress, avoiding
// repeated full auth-file payloads while the management page is polling.
func (h *Handler) ListAgentIdentityRegistrations(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	views := h.authManager.ListRuntimeViews()
	results := make([]agentIdentityRegistrationResult, 0, len(views))
	active := 0
	for _, auth := range views {
		runtime, ok := auth.Runtime.(agentIdentityRegistrationRuntime)
		if !ok || runtime == nil {
			continue
		}
		status := runtime.RegistrationStatus()
		if status.Active {
			active++
		}
		results = append(results, agentIdentityRegistrationResult{
			Name:         runtimeAuthViewDisplayName(auth),
			Registration: status,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"active":        active,
		"registrations": results,
	})
}

func runtimeAuthViewDisplayName(auth coreauth.RuntimeAuthView) string {
	if name := strings.TrimSpace(auth.FileName); name != "" {
		return name
	}
	return strings.TrimSpace(auth.ID)
}

// RegisterAgentIdentityTask retries one failed Agent Identity task registration.
func (h *Handler) RegisterAgentIdentityTask(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	result, statusCode, errMessage := h.retryAgentIdentityRegistration(name)
	if errMessage != "" {
		c.JSON(statusCode, gin.H{"error": errMessage})
		return
	}
	if result.Queued || result.Registration.Active {
		statusCode = http.StatusAccepted
	} else {
		statusCode = http.StatusOK
	}
	c.JSON(statusCode, result)
}

// RegisterAgentIdentityTasks retries selected Agent Identity registrations.
func (h *Handler) RegisterAgentIdentityTasks(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	var req struct {
		Names []string `json:"names"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	names := uniqueAgentIdentityRegistrationNames(req.Names)
	if len(names) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "names are required"})
		return
	}
	if len(names) > maxAgentIdentityRegistrationBatch {
		c.JSON(http.StatusBadRequest, gin.H{"error": "too many auth files in one request"})
		return
	}

	results := make([]agentIdentityRegistrationResult, 0, len(names))
	failures := make([]gin.H, 0)
	queued := 0
	skipped := 0
	for _, name := range names {
		result, _, errMessage := h.retryAgentIdentityRegistration(name)
		if errMessage != "" {
			failures = append(failures, gin.H{"name": name, "error": errMessage})
			continue
		}
		if result.Queued {
			queued++
		} else if !result.Registration.Active {
			skipped++
		}
		results = append(results, result)
	}

	statusCode := http.StatusOK
	if queued > 0 {
		statusCode = http.StatusAccepted
	}
	c.JSON(statusCode, gin.H{
		"status":  "ok",
		"queued":  queued,
		"skipped": skipped,
		"results": results,
		"failed":  failures,
	})
}

func (h *Handler) retryAgentIdentityRegistration(name string) (agentIdentityRegistrationResult, int, string) {
	auth := h.findAuthForAgentIdentityRegistration(name)
	if auth == nil {
		return agentIdentityRegistrationResult{}, http.StatusNotFound, "auth file not found"
	}
	runtime, ok := auth.Runtime.(agentIdentityRegistrationRuntime)
	if !ok || runtime == nil {
		return agentIdentityRegistrationResult{}, http.StatusConflict, "auth file is not an agent identity account"
	}
	runtime.SetRegistrationClient(h.agentIdentityRegistrationClient(auth))
	status, queued := runtime.RetryTaskRegistration()
	return agentIdentityRegistrationResult{
		Name:         authFileDisplayName(auth),
		Queued:       queued,
		Registration: status,
	}, http.StatusOK, ""
}

func (h *Handler) agentIdentityRegistrationClient(auth *coreauth.Auth) *http.Client {
	client := &http.Client{}
	proxyURL := strings.TrimSpace(auth.ProxyURL)
	if proxyURL == "" && h != nil && h.cfg != nil {
		proxyURL = strings.TrimSpace(h.cfg.ProxyURL)
	}
	if proxyURL != "" {
		if transport := buildProxyTransport(proxyURL); transport != nil {
			client.Transport = transport
		}
	}
	return client
}

func (h *Handler) findAuthForAgentIdentityRegistration(name string) *coreauth.Auth {
	if h == nil || h.authManager == nil {
		return nil
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	if auth, ok := h.authManager.GetByID(name); ok {
		return auth
	}
	for _, auth := range h.authManager.List() {
		if auth == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(auth.FileName), name) ||
			strings.EqualFold(strings.TrimSpace(auth.ID), name) {
			return auth
		}
	}
	return nil
}

func authFileDisplayName(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if name := strings.TrimSpace(auth.FileName); name != "" {
		return name
	}
	return strings.TrimSpace(auth.ID)
}

func uniqueAgentIdentityRegistrationNames(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		name := strings.TrimSpace(value)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, name)
	}
	return result
}
