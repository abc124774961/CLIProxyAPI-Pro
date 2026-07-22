package codex

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	AuthModeAgentIdentity = "agentIdentity"

	agentIdentityAuthAPIBaseURL  = "https://auth.openai.com/api/accounts"
	agentIdentityRegisterLimit   = 64 << 10
	agentIdentityRegisterTimeout = 30 * time.Second
)

var agentIdentityAuthAPIBaseURLForTest string

// ErrAgentIdentityCredentialsMissing marks an import that identifies itself as
// Agent Identity but does not yet contain enough signing material to serve
// traffic. Management imports may persist this state for later recovery, while
// malformed signing material remains a hard validation error.
var ErrAgentIdentityCredentialsMissing = errors.New("agent identity runtime id or private key is missing")

// AgentIdentityCredentials contains the non-OAuth fields exported for a K12
// agent identity. PrivateKey is a base64-encoded PKCS#8 Ed25519 private key.
type AgentIdentityCredentials struct {
	RuntimeID  string
	PrivateKey string
	TaskID     string
}

// AgentIdentity owns parsed signing material and task registration state for
// one auth record. It is safe for concurrent request use.
type AgentIdentity struct {
	runtimeID         string
	encodedPrivateKey string
	privateKey        ed25519.PrivateKey

	mu     sync.RWMutex
	taskID string

	registrationMu          sync.Mutex
	persist                 func(context.Context, string, string) error
	registrationClient      *http.Client
	registrationCoordinator *agentIdentityRegistrationCoordinator
	registrationStatus      AgentIdentityRegistrationStatus
	registrationEnqueued    bool
	registrationRetryTimer  *time.Timer
	registrationGeneration  uint64
	registrationDone        chan struct{}
	registrationName        string
	selectionAvailable      atomic.Bool
}

type agentIdentityTaskRegistrationResponse struct {
	TaskID               string `json:"task_id"`
	TaskIDCamel          string `json:"taskId"`
	EncryptedTaskID      string `json:"encrypted_task_id"`
	EncryptedTaskIDCamel string `json:"encryptedTaskId"`
}

// NewAgentIdentity validates and caches the signing key without logging it.
func NewAgentIdentity(credentials AgentIdentityCredentials) (*AgentIdentity, error) {
	runtimeID := strings.TrimSpace(credentials.RuntimeID)
	encodedPrivateKey := strings.TrimSpace(credentials.PrivateKey)
	if runtimeID == "" {
		return nil, errors.New("agent identity runtime id is missing")
	}
	privateKey, err := parseAgentIdentityPrivateKey(encodedPrivateKey)
	if err != nil {
		return nil, err
	}
	taskID := strings.TrimSpace(credentials.TaskID)
	identity := &AgentIdentity{
		runtimeID:               runtimeID,
		encodedPrivateKey:       encodedPrivateKey,
		privateKey:              privateKey,
		taskID:                  taskID,
		registrationCoordinator: defaultAgentIdentityRegistrationCoordinator,
		registrationStatus:      initialAgentIdentityRegistrationStatus(taskID != ""),
	}
	identity.selectionAvailable.Store(taskID != "")
	return identity, nil
}

// ValidateAgentIdentityPrivateKey validates an exported key without exposing
// any key material in the returned error.
func ValidateAgentIdentityPrivateKey(encoded string) error {
	_, err := parseAgentIdentityPrivateKey(encoded)
	return err
}

func parseAgentIdentityPrivateKey(encoded string) (ed25519.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, errors.New("agent identity private key is not valid base64")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("agent identity private key is not valid PKCS#8")
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("agent identity private key is not Ed25519")
	}
	return privateKey, nil
}

// SetTaskPersister installs a callback used after task replacement. The
// callback must not log credentials or assertion values.
func (a *AgentIdentity) SetTaskPersister(persist func(context.Context, string, string) error) {
	if a == nil {
		return
	}
	a.registrationMu.Lock()
	a.persist = persist
	a.registrationMu.Unlock()
}

// Matches reports whether this runtime belongs to the supplied credentials.
func (a *AgentIdentity) Matches(credentials AgentIdentityCredentials) bool {
	if a == nil {
		return false
	}
	return a.runtimeID == strings.TrimSpace(credentials.RuntimeID) &&
		a.encodedPrivateKey == strings.TrimSpace(credentials.PrivateKey)
}

// MatchesRuntime reports whether an auth-file refresh describes the exact
// runtime currently installed, including its task. It lets the file watcher
// retain the live recovery state when task persistence rewrites the auth file,
// while still honoring an externally replaced task or signing identity.
func (a *AgentIdentity) MatchesRuntime(other *AgentIdentity) bool {
	if a == nil || other == nil {
		return false
	}
	if a == other {
		return true
	}
	return a.runtimeID == other.runtimeID &&
		a.encodedPrivateKey == other.encodedPrivateKey &&
		a.key().taskID == other.key().taskID
}

func (a *AgentIdentity) key() agentIdentityKey {
	a.mu.RLock()
	taskID := a.taskID
	a.mu.RUnlock()
	return agentIdentityKey{
		runtimeID:  a.runtimeID,
		privateKey: a.privateKey,
		taskID:     taskID,
	}
}

type agentIdentityKey struct {
	runtimeID  string
	privateKey ed25519.PrivateKey
	taskID     string
}

func buildAgentAssertion(key agentIdentityKey, now time.Time) (string, error) {
	if key.runtimeID == "" || key.taskID == "" {
		return "", errors.New("agent identity runtime or task id is missing")
	}
	timestamp := now.UTC().Format(time.RFC3339)
	payload := []byte(key.runtimeID + ":" + key.taskID + ":" + timestamp)
	signature := ed25519.Sign(key.privateKey, payload)
	envelope := map[string]string{
		"agent_runtime_id": key.runtimeID,
		"task_id":          key.taskID,
		"timestamp":        timestamp,
		"signature":        base64.StdEncoding.EncodeToString(signature),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", errors.New("failed to serialize agent assertion")
	}
	return "AgentAssertion " + base64.RawURLEncoding.EncodeToString(encoded), nil
}

func signAgentTaskRegistration(key agentIdentityKey, now time.Time) (timestamp, signature string) {
	timestamp = now.UTC().Format(time.RFC3339)
	signed := ed25519.Sign(key.privateKey, []byte(key.runtimeID+":"+timestamp))
	return timestamp, base64.StdEncoding.EncodeToString(signed)
}

func decryptAgentTaskID(key agentIdentityKey, encoded string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", errors.New("encrypted agent task id is not valid base64")
	}

	digest := sha512.Sum512(key.privateKey.Seed())
	var curvePrivate [32]byte
	copy(curvePrivate[:], digest[:32])
	curvePrivate[0] &= 248
	curvePrivate[31] &= 127
	curvePrivate[31] |= 64
	curvePublicBytes, err := curve25519.X25519(curvePrivate[:], curve25519.Basepoint)
	if err != nil {
		return "", errors.New("failed to derive agent identity decryption key")
	}
	var curvePublic [32]byte
	copy(curvePublic[:], curvePublicBytes)
	plaintext, ok := box.OpenAnonymous(nil, ciphertext, &curvePublic, &curvePrivate)
	if !ok {
		return "", errors.New("failed to decrypt encrypted agent task id")
	}
	taskID := strings.TrimSpace(string(plaintext))
	if taskID == "" {
		return "", errors.New("decrypted agent task id is empty")
	}
	return taskID, nil
}

func registerAgentIdentityTask(ctx context.Context, client *http.Client, key agentIdentityKey) (string, error) {
	if client == nil {
		return "", &agentIdentityRegistrationError{
			code:    "client_unavailable",
			message: "Task registration client is unavailable.",
		}
	}
	timestamp, signature := signAgentTaskRegistration(key, time.Now())
	body, err := json.Marshal(map[string]string{
		"timestamp": timestamp,
		"signature": signature,
	})
	if err != nil {
		return "", errors.New("failed to serialize agent task registration")
	}

	baseURL := agentIdentityAuthAPIBaseURL
	if strings.TrimSpace(agentIdentityAuthAPIBaseURLForTest) != "" {
		baseURL = strings.TrimRight(strings.TrimSpace(agentIdentityAuthAPIBaseURLForTest), "/")
	}
	endpoint := baseURL + "/v1/agent/" + url.PathEscape(key.runtimeID) + "/task/register"
	requestCtx, cancel := context.WithTimeout(ctx, agentIdentityRegisterTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", errors.New("failed to build agent task registration request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", &agentIdentityRegistrationError{
			code:      "network_error",
			message:   "Task registration request failed.",
			retryable: true,
			cause:     err,
		}
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.WithError(errClose).Debug("failed to close agent task registration response")
		}
	}()
	body, errRead := io.ReadAll(io.LimitReader(resp.Body, agentIdentityRegisterLimit+1))
	if errRead != nil {
		return "", &agentIdentityRegistrationError{
			code:      "response_read_error",
			message:   "Task registration response could not be read.",
			retryable: true,
			cause:     errRead,
		}
	}
	if len(body) > agentIdentityRegisterLimit {
		return "", &agentIdentityRegistrationError{
			code:    "response_too_large",
			message: "Task registration response is too large.",
		}
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", classifyAgentIdentityRegistrationResponse(resp.StatusCode, body)
	}
	var result agentIdentityTaskRegistrationResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", &agentIdentityRegistrationError{
			code:      "invalid_response",
			message:   "Task registration response is invalid.",
			retryable: true,
			cause:     err,
		}
	}
	if taskID := strings.TrimSpace(result.TaskID); taskID != "" {
		return taskID, nil
	}
	if taskID := strings.TrimSpace(result.TaskIDCamel); taskID != "" {
		return taskID, nil
	}
	encrypted := strings.TrimSpace(result.EncryptedTaskID)
	if encrypted == "" {
		encrypted = strings.TrimSpace(result.EncryptedTaskIDCamel)
	}
	if encrypted == "" {
		return "", &agentIdentityRegistrationError{
			code:      "task_omitted",
			message:   "Task registration response omitted the task.",
			retryable: true,
		}
	}
	return decryptAgentTaskID(key, encrypted)
}

func classifyAgentIdentityRegistrationResponse(statusCode int, body []byte) error {
	if IsAgentIdentityRuntimeDeletedResponse(statusCode, body) {
		return &agentIdentityRegistrationError{
			code:    "runtime_deleted",
			message: "Agent runtime has been deleted. Import fresh credentials to recover this account.",
		}
	}
	if statusCode == http.StatusRequestTimeout || statusCode == http.StatusTooManyRequests || statusCode >= http.StatusInternalServerError {
		return &agentIdentityRegistrationError{
			code:      fmt.Sprintf("http_%d", statusCode),
			message:   "Task registration service is temporarily unavailable.",
			retryable: true,
		}
	}
	return &agentIdentityRegistrationError{
		code:    fmt.Sprintf("http_%d", statusCode),
		message: "Task registration was rejected.",
	}
}

// Authorization returns a fresh AgentAssertion and the task used to build it.
// The task value is only for one-time stale-task recovery and must not be logged.
func (a *AgentIdentity) Authorization(ctx context.Context, client *http.Client) (headerValue, taskID string, err error) {
	if a == nil {
		return "", "", errors.New("agent identity is nil")
	}
	key := a.key()
	if key.taskID == "" {
		a.QueueTaskRegistration(client, "")
		if err := a.waitForTaskRegistration(ctx); err != nil {
			return "", "", err
		}
		key = a.key()
	}
	assertion, err := buildAgentAssertion(key, time.Now())
	if err != nil {
		return "", "", err
	}
	return assertion, key.taskID, nil
}

// RecoverAuthorization replaces an explicitly rejected task and returns a
// fresh assertion. Registration remains bounded by the shared worker pool,
// while concurrent callers wait on the same recovery generation.
func (a *AgentIdentity) RecoverAuthorization(ctx context.Context, client *http.Client, staleTaskID string) (string, error) {
	a.QueueTaskRegistration(client, strings.TrimSpace(staleTaskID))
	if err := a.waitForTaskRegistration(ctx); err != nil {
		return "", err
	}
	return buildAgentAssertion(a.key(), time.Now())
}

// IsAgentIdentityTaskInvalidResponse recognizes only errors that safely allow
// task replacement and one retry.
func IsAgentIdentityTaskInvalidResponse(statusCode int, body []byte) bool {
	if statusCode != http.StatusUnauthorized {
		return false
	}
	lower := strings.ToLower(string(body))
	compact := strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "").Replace(lower)
	for _, marker := range []string{
		`"code":"invalid_task_id"`,
		`"code":"task_not_found"`,
		`"code":"task_expired"`,
		`"error":"invalid_task_id"`,
	} {
		if strings.Contains(compact, marker) {
			return true
		}
	}
	for _, marker := range []string{
		"invalid task_id", "invalid task id", "task_id is invalid", "task id is invalid",
		"task not found", "task expired", "unknown task_id", "unknown task id",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// IsAgentIdentityRuntimeDeletedResponse recognizes the terminal Agent Identity
// response without exposing its credential-bearing payload.
func IsAgentIdentityRuntimeDeletedResponse(_ int, body []byte) bool {
	lower := strings.ToLower(string(body))
	compact := strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "").Replace(lower)
	return strings.Contains(lower, "agent runtime has been deleted") ||
		strings.Contains(lower, "agent_runtime has been deleted") ||
		strings.Contains(compact, `"code":"deleted_agent_runtime_id"`) ||
		(strings.Contains(compact, "biscuit_baker_service_agent_error_status") &&
			strings.Contains(compact, "runtime_deleted"))
}

// RedactSensitiveBody removes credential values if an upstream error echoes
// them unexpectedly.
func (a *AgentIdentity) RedactSensitiveBody(body []byte) []byte {
	if a == nil || len(body) == 0 {
		return body
	}
	key := a.key()
	redacted := string(body)
	for _, value := range []string{a.runtimeID, a.encodedPrivateKey, key.taskID} {
		if value = strings.TrimSpace(value); value != "" {
			redacted = strings.ReplaceAll(redacted, value, "[redacted]")
		}
	}
	const prefix = "AgentAssertion "
	for offset := 0; offset < len(redacted); {
		relativeStart := strings.Index(redacted[offset:], prefix)
		if relativeStart < 0 {
			break
		}
		valueStart := offset + relativeStart + len(prefix)
		end := valueStart
		for end < len(redacted) && !strings.ContainsRune(" \t\r\n\"',}", rune(redacted[end])) {
			end++
		}
		redacted = redacted[:valueStart] + "[redacted]" + redacted[end:]
		offset = valueStart + len("[redacted]")
	}
	return []byte(redacted)
}

// ParseAgentIdentityMetadata accepts flat snake/camel case fields and the
// nested agent_identity/agentIdentity variants used by Sub2 exports.
func ParseAgentIdentityMetadata(metadata map[string]any) (AgentIdentityCredentials, bool, error) {
	if metadata == nil {
		return AgentIdentityCredentials{}, false, nil
	}
	nested := firstMap(metadata, "agent_identity", "agentIdentity")
	authMode := firstString(metadata, "auth_mode", "authMode")
	credentials := AgentIdentityCredentials{
		RuntimeID: firstNonEmpty(
			firstString(metadata, "agent_runtime_id", "agentRuntimeId"),
			firstString(nested, "agent_runtime_id", "agentRuntimeId"),
		),
		PrivateKey: firstNonEmpty(
			firstString(metadata, "agent_private_key", "agentPrivateKey"),
			firstString(nested, "agent_private_key", "agentPrivateKey"),
		),
		TaskID: firstNonEmpty(
			firstString(metadata, "task_id", "taskId"),
			firstString(nested, "task_id", "taskId"),
		),
	}
	handled := strings.EqualFold(authMode, AuthModeAgentIdentity) || credentials.RuntimeID != "" || credentials.PrivateKey != ""
	if !handled {
		return AgentIdentityCredentials{}, false, nil
	}
	if credentials.PrivateKey != "" {
		if err := ValidateAgentIdentityPrivateKey(credentials.PrivateKey); err != nil {
			return credentials, true, err
		}
	}
	if credentials.RuntimeID == "" || credentials.PrivateKey == "" {
		return credentials, true, ErrAgentIdentityCredentialsMissing
	}
	return credentials, true, nil
}

func firstMap(values map[string]any, keys ...string) map[string]any {
	for _, key := range keys {
		if value, ok := values[key].(map[string]any); ok {
			return value
		}
	}
	return nil
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key].(string); ok {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
