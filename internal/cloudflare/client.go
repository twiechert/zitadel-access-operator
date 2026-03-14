package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const baseURL = "https://api.cloudflare.com/client/v4"

// AccessApp represents a Cloudflare Access Application.
type AccessApp struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// AccessPolicy represents a Cloudflare Access Policy.
type AccessPolicy struct {
	ID string `json:"id"`
}

// OIDCClaimRule defines an inline OIDC claim check for an Access Policy.
type OIDCClaimRule struct {
	IdentityProviderID string `json:"identity_provider_id"`
	ClaimName          string `json:"claim_name"`
	ClaimValue         string `json:"claim_value"`
}

// Client talks to the Cloudflare Access API.
type Client interface {
	// FindAccessAppByDomain returns the Access Application for the given domain, or nil.
	FindAccessAppByDomain(ctx context.Context, domain string) (*AccessApp, error)

	// CreateAccessApp creates a self-hosted Access Application.
	CreateAccessApp(ctx context.Context, name, domain, sessionDuration string) (*AccessApp, error)

	// UpdateAccessApp updates an existing Access Application.
	UpdateAccessApp(ctx context.Context, appID, name, domain, sessionDuration string) error

	// DeleteAccessApp deletes an Access Application.
	DeleteAccessApp(ctx context.Context, appID string) error

	// UpsertAccessPolicy creates or updates the allow policy on an Access Application
	// with inline OIDC claim rules (one per role).
	UpsertAccessPolicy(ctx context.Context, appID string, existingPolicyID string, rules []OIDCClaimRule) (*AccessPolicy, error)

	// CreateBypassApp creates a self-hosted Access Application with a bypass policy
	// that allows unauthenticated access. The domain should include the path
	// (e.g. "example.com/webhook").
	CreateBypassApp(ctx context.Context, name, domain string) (*AccessApp, error)
}

// NewClient creates a Cloudflare API client.
func NewClient(apiToken, accountID string) Client {
	return &httpClient{
		apiToken:  apiToken,
		accountID: accountID,
		http:      &http.Client{},
	}
}

type httpClient struct {
	apiToken  string
	accountID string
	http      *http.Client
}

func (c *httpClient) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("cloudflare API %s %s returned %d: %s", method, path, resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func (c *httpClient) accountPath(suffix string) string {
	return fmt.Sprintf("/accounts/%s/access%s", c.accountID, suffix)
}

func (c *httpClient) FindAccessAppByDomain(ctx context.Context, domain string) (*AccessApp, error) {
	respBody, err := c.do(ctx, http.MethodGet, c.accountPath("/apps"), nil)
	if err != nil {
		return nil, fmt.Errorf("list access apps: %w", err)
	}

	var result struct {
		Result []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Domain string `json:"domain"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal access apps: %w", err)
	}

	for _, app := range result.Result {
		if app.Domain == domain {
			return &AccessApp{ID: app.ID, Name: app.Name}, nil
		}
	}
	return nil, nil
}

func (c *httpClient) CreateAccessApp(ctx context.Context, name, domain, sessionDuration string) (*AccessApp, error) {
	body := map[string]any{
		"name":             name,
		"domain":           domain,
		"type":             "self_hosted",
		"session_duration": sessionDuration,
	}

	respBody, err := c.do(ctx, http.MethodPost, c.accountPath("/apps"), body)
	if err != nil {
		return nil, fmt.Errorf("create access app: %w", err)
	}

	var result struct {
		Result struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal create response: %w", err)
	}

	return &AccessApp{ID: result.Result.ID, Name: result.Result.Name}, nil
}

func (c *httpClient) UpdateAccessApp(ctx context.Context, appID, name, domain, sessionDuration string) error {
	body := map[string]any{
		"name":             name,
		"domain":           domain,
		"type":             "self_hosted",
		"session_duration": sessionDuration,
	}

	_, err := c.do(ctx, http.MethodPut, c.accountPath("/apps/"+appID), body)
	if err != nil {
		return fmt.Errorf("update access app: %w", err)
	}
	return nil
}

func (c *httpClient) DeleteAccessApp(ctx context.Context, appID string) error {
	_, err := c.do(ctx, http.MethodDelete, c.accountPath("/apps/"+appID), nil)
	if err != nil {
		return fmt.Errorf("delete access app: %w", err)
	}
	return nil
}

func (c *httpClient) UpsertAccessPolicy(ctx context.Context, appID string, existingPolicyID string, rules []OIDCClaimRule) (*AccessPolicy, error) {
	include := make([]map[string]any, len(rules))
	for i, rule := range rules {
		include[i] = map[string]any{
			"oidc": map[string]any{
				"identity_provider_id": rule.IdentityProviderID,
				"claim_name":           rule.ClaimName,
				"claim_value":          rule.ClaimValue,
			},
		}
	}

	body := map[string]any{
		"name":       "Allow Zitadel roles",
		"decision":   "allow",
		"precedence": 1,
		"include":    include,
	}

	if existingPolicyID != "" {
		// Update existing policy.
		path := c.accountPath(fmt.Sprintf("/apps/%s/policies/%s", appID, existingPolicyID))
		_, err := c.do(ctx, http.MethodPut, path, body)
		if err != nil {
			return nil, fmt.Errorf("update access policy: %w", err)
		}
		return &AccessPolicy{ID: existingPolicyID}, nil
	}

	// Create new policy.
	path := c.accountPath(fmt.Sprintf("/apps/%s/policies", appID))
	respBody, err := c.do(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, fmt.Errorf("create access policy: %w", err)
	}

	var result struct {
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal policy response: %w", err)
	}

	return &AccessPolicy{ID: result.Result.ID}, nil
}

func (c *httpClient) CreateBypassApp(ctx context.Context, name, domain string) (*AccessApp, error) {
	body := map[string]any{
		"name":             name,
		"domain":           domain,
		"type":             "self_hosted",
		"session_duration": "24h",
	}

	respBody, err := c.do(ctx, http.MethodPost, c.accountPath("/apps"), body)
	if err != nil {
		return nil, fmt.Errorf("create bypass access app: %w", err)
	}

	var result struct {
		Result struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal bypass app response: %w", err)
	}

	// Create bypass policy on the app.
	policyBody := map[string]any{
		"name":       "Bypass",
		"decision":   "bypass",
		"precedence": 1,
		"include":    []map[string]any{{"everyone": map[string]any{}}},
	}
	path := c.accountPath(fmt.Sprintf("/apps/%s/policies", result.Result.ID))
	if _, err := c.do(ctx, http.MethodPost, path, policyBody); err != nil {
		// Clean up the app if policy creation fails.
		_ = c.DeleteAccessApp(ctx, result.Result.ID)
		return nil, fmt.Errorf("create bypass policy: %w", err)
	}

	return &AccessApp{ID: result.Result.ID, Name: result.Result.Name}, nil
}
