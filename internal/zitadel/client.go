package zitadel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ErrNotFound is returned when the Zitadel API returns 404.
var ErrNotFound = errors.New("zitadel resource not found")

// Project represents a Zitadel project.
type Project struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Role represents a Zitadel project role.
type Role struct {
	Key         string `json:"key"`
	DisplayName string `json:"displayName"`
}

// App represents a Zitadel OIDC application.
type App struct {
	ID           string `json:"id"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret,omitempty"`
}

// AppConfig holds the desired OIDC app configuration.
type AppConfig struct {
	Name                     string   `json:"name"`
	RedirectURIs             []string `json:"redirectUris"`
	PostLogoutRedirectURIs   []string `json:"postLogoutRedirectUris,omitempty"`
	ResponseTypes            []string `json:"responseTypes,omitempty"`
	GrantTypes               []string `json:"grantTypes,omitempty"`
	AppType                  string   `json:"appType,omitempty"`
	AuthMethodType           string   `json:"authMethodType,omitempty"`
	AccessTokenType          string   `json:"accessTokenType,omitempty"`
	DevMode                  bool     `json:"devMode,omitempty"`
	IDTokenRoleAssertion     bool     `json:"idTokenRoleAssertion,omitempty"`
	IDTokenUserinfoAssertion bool     `json:"idTokenUserinfoAssertion,omitempty"`
	AccessTokenRoleAssertion bool     `json:"accessTokenRoleAssertion,omitempty"`
}

// Client talks to the Zitadel Management API.
type Client interface {
	GetProjectByName(ctx context.Context, name string) (*Project, error)
	ListProjectRoles(ctx context.Context, projectID string) ([]Role, error)
	GetAppByName(ctx context.Context, projectID, name string) (*App, error)
	CreateApp(ctx context.Context, projectID string, config AppConfig) (*App, error)
	UpdateApp(ctx context.Context, projectID, appID string, config AppConfig) error
	DeleteApp(ctx context.Context, projectID, appID string) error
}

// NewClient creates a Zitadel Management API client using a Personal Access Token.
func NewClient(baseURL, token string) Client {
	return &httpClient{
		baseURL: baseURL,
		token:   token,
		http:    &http.Client{},
	}
}

type httpClient struct {
	baseURL string
	token   string
	http    *http.Client
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

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("zitadel API %s %s returned %d: %s: %w", method, path, resp.StatusCode, string(respBody), ErrNotFound)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("zitadel API %s %s returned %d: %s", method, path, resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func (c *httpClient) GetProjectByName(ctx context.Context, name string) (*Project, error) {
	body := map[string]any{
		"queries": []map[string]any{
			{
				"nameQuery": map[string]any{
					"name":   name,
					"method": "TEXT_QUERY_METHOD_EQUALS",
				},
			},
		},
	}

	respBody, err := c.do(ctx, http.MethodPost, "/management/v1/projects/_search", body)
	if err != nil {
		return nil, fmt.Errorf("search projects: %w", err)
	}

	var result struct {
		Result []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal project search: %w", err)
	}

	if len(result.Result) == 0 {
		return nil, nil
	}

	return &Project{
		ID:   result.Result[0].ID,
		Name: result.Result[0].Name,
	}, nil
}

func (c *httpClient) ListProjectRoles(ctx context.Context, projectID string) ([]Role, error) {
	path := fmt.Sprintf("/management/v1/projects/%s/roles/_search", projectID)
	respBody, err := c.do(ctx, http.MethodPost, path, map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("search roles: %w", err)
	}

	var result struct {
		Result []struct {
			Key         string `json:"key"`
			DisplayName string `json:"displayName"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal role search: %w", err)
	}

	roles := make([]Role, len(result.Result))
	for i, r := range result.Result {
		roles[i] = Role{Key: r.Key, DisplayName: r.DisplayName}
	}
	return roles, nil
}

func (c *httpClient) GetAppByName(ctx context.Context, projectID, name string) (*App, error) {
	path := fmt.Sprintf("/management/v1/projects/%s/apps/_search", projectID)
	body := map[string]any{
		"queries": []map[string]any{
			{
				"nameQuery": map[string]any{
					"name":   name,
					"method": "TEXT_QUERY_METHOD_EQUALS",
				},
			},
		},
	}

	respBody, err := c.do(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, fmt.Errorf("search apps: %w", err)
	}

	var result struct {
		Result []struct {
			ID         string `json:"id"`
			OIDCConfig struct {
				ClientID string `json:"clientId"`
			} `json:"oidcConfig"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal app search: %w", err)
	}

	if len(result.Result) == 0 {
		return nil, nil
	}

	return &App{
		ID:       result.Result[0].ID,
		ClientID: result.Result[0].OIDCConfig.ClientID,
	}, nil
}

func (c *httpClient) CreateApp(ctx context.Context, projectID string, config AppConfig) (*App, error) {
	path := fmt.Sprintf("/management/v1/projects/%s/apps/oidc", projectID)
	respBody, err := c.do(ctx, http.MethodPost, path, config)
	if err != nil {
		return nil, fmt.Errorf("create app: %w", err)
	}

	var result struct {
		AppID        string `json:"appId"`
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal create response: %w", err)
	}

	return &App{
		ID:           result.AppID,
		ClientID:     result.ClientID,
		ClientSecret: result.ClientSecret,
	}, nil
}

func (c *httpClient) UpdateApp(ctx context.Context, projectID, appID string, config AppConfig) error {
	path := fmt.Sprintf("/management/v1/projects/%s/apps/%s/oidc_config", projectID, appID)
	_, err := c.do(ctx, http.MethodPut, path, config)
	if err != nil {
		// Zitadel returns 400 "No changes" when the config is already identical.
		// Treat this as a successful no-op.
		if strings.Contains(err.Error(), "No changes") {
			return nil
		}
		return fmt.Errorf("update app: %w", err)
	}
	return nil
}

func (c *httpClient) DeleteApp(ctx context.Context, projectID, appID string) error {
	path := fmt.Sprintf("/management/v1/projects/%s/apps/%s", projectID, appID)
	_, err := c.do(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("delete app: %w", err)
	}
	return nil
}
