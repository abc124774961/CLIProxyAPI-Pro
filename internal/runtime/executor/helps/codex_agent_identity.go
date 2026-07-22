package helps

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	codexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const codexAgentIdentityErrorBodyLimit int64 = 64 << 10

// CodexAgentIdentity is the execution contract exposed by the K12 auth
// runtime. A wrapper may also implement refresh policy interfaces.
type CodexAgentIdentity interface {
	Authorization(context.Context, *http.Client) (string, string, error)
	RecoverAuthorization(context.Context, *http.Client, string) (string, error)
	MarkRuntimeDeleted()
	RedactSensitiveBody([]byte) []byte
}

// PrepareCodexAuthorization returns either a normal Bearer authorization or a
// freshly signed AgentAssertion for a K12 agent identity auth.
func PrepareCodexAuthorization(ctx context.Context, auth *cliproxyauth.Auth, client *http.Client, token string) (authorization, taskID string, err error) {
	runtime, ok := CodexAgentIdentityRuntime(auth)
	if !ok {
		if strings.TrimSpace(token) == "" {
			return "", "", nil
		}
		return "Bearer " + strings.TrimSpace(token), "", nil
	}
	return runtime.Authorization(ctx, client)
}

// CodexAgentIdentityRuntime returns the validated runtime attached by the file
// synthesizer. Agent identity credentials are never reconstructed in logs.
func CodexAgentIdentityRuntime(auth *cliproxyauth.Auth) (CodexAgentIdentity, bool) {
	if auth == nil || auth.Runtime == nil {
		return nil, false
	}
	runtime, ok := auth.Runtime.(CodexAgentIdentity)
	return runtime, ok && runtime != nil
}

// DoCodexRequestWithAgentRecovery performs one upstream request and replaces a
// rejected agent task at most once. Recovery uses the bounded background pool,
// but this request waits for that shared recovery and replays once before
// falling back to another credential.
func DoCodexRequestWithAgentRecovery(
	ctx context.Context,
	auth *cliproxyauth.Auth,
	authClient *http.Client,
	upstreamClient *http.Client,
	req *http.Request,
	staleTaskID string,
) (*http.Response, error) {
	if upstreamClient == nil {
		return nil, errors.New("codex upstream HTTP client is nil")
	}
	if req == nil {
		return nil, errors.New("codex upstream request is nil")
	}
	resp, err := upstreamClient.Do(req)
	if err != nil {
		return nil, err
	}
	runtime, isAgentIdentity := CodexAgentIdentityRuntime(auth)
	if !isAgentIdentity || resp.StatusCode < http.StatusBadRequest {
		return redactCodexAgentIdentityErrorResponse(runtime, resp), nil
	}

	body, errRead := readAndCloseCodexAgentIdentityError(resp)
	if errRead != nil {
		return nil, errRead
	}
	if codexauth.IsAgentIdentityRuntimeDeletedResponse(resp.StatusCode, body) {
		runtime.MarkRuntimeDeleted()
		return restoreCodexAgentIdentityErrorResponse(resp, runtime.RedactSensitiveBody(body)), nil
	}
	if !codexauth.IsAgentIdentityTaskInvalidResponse(resp.StatusCode, body) {
		return restoreCodexAgentIdentityErrorResponse(resp, runtime.RedactSensitiveBody(body)), nil
	}
	if authClient == nil {
		return nil, errors.New("codex agent identity HTTP client is nil")
	}
	authorization, errRecover := runtime.RecoverAuthorization(ctx, authClient, staleTaskID)
	if errRecover != nil {
		return nil, fmt.Errorf("recover codex agent identity task: %w", errRecover)
	}
	retryReq, errClone := cloneCodexRequestForRetry(ctx, req)
	if errClone != nil {
		return nil, errClone
	}
	retryReq.Header.Set("Authorization", authorization)
	retryResp, errRetry := upstreamClient.Do(retryReq)
	if errRetry != nil {
		return nil, errRetry
	}
	return redactCodexAgentIdentityErrorResponse(runtime, retryResp), nil
}

func cloneCodexRequestForRetry(ctx context.Context, req *http.Request) (*http.Request, error) {
	if req.GetBody == nil {
		return nil, errors.New("codex agent identity request body cannot be replayed")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, fmt.Errorf("reopen codex request body: %w", err)
	}
	retryReq := req.Clone(ctx)
	retryReq.Body = body
	retryReq.GetBody = req.GetBody
	return retryReq, nil
}

func redactCodexAgentIdentityErrorResponse(runtime CodexAgentIdentity, resp *http.Response) *http.Response {
	if runtime == nil || resp == nil || resp.StatusCode < http.StatusBadRequest || resp.Body == nil {
		return resp
	}
	body, err := readAndCloseCodexAgentIdentityError(resp)
	if err != nil {
		return restoreCodexAgentIdentityErrorResponse(resp, runtime.RedactSensitiveBody(body))
	}
	return restoreCodexAgentIdentityErrorResponse(resp, runtime.RedactSensitiveBody(body))
}

func readAndCloseCodexAgentIdentityError(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, codexAgentIdentityErrorBodyLimit))
	if errClose := resp.Body.Close(); err == nil && errClose != nil {
		err = errClose
	}
	return body, err
}

func restoreCodexAgentIdentityErrorResponse(resp *http.Response, body []byte) *http.Response {
	if resp == nil {
		return nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	if resp.Header != nil {
		resp.Header.Del("Content-Length")
	}
	return resp
}
