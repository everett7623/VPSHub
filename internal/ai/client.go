package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Config for OpenAI-compatible chat completions.
type Config struct {
	Enabled bool
	BaseURL string
	APIKey  string
	Model   string
}

// Client talks to an OpenAI-compatible /chat/completions endpoint.
type Client struct {
	Cfg    Config
	HTTP   *http.Client
}

func New(cfg Config) *Client {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.openai.com/v1"
	}
	if cfg.Model == "" {
		cfg.Model = "gpt-4o-mini"
	}
	return &Client{
		Cfg: cfg,
		HTTP: &http.Client{Timeout: 90 * time.Second},
	}
}

func (c *Client) Enabled() bool {
	return c != nil && c.Cfg.Enabled && c.Cfg.APIKey != ""
}

type chatReq struct {
	Model    string    `json:"model"`
	Messages []chatMsg `json:"messages"`
}

type chatMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResp struct {
	Choices []struct {
		Message chatMsg `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Advise asks the model for ops recommendations. It must not claim to have executed anything.
func (c *Client) Advise(ctx context.Context, system, user string) (string, error) {
	if !c.Enabled() {
		return "", fmt.Errorf("ai disabled or api key missing")
	}
	body, _ := json.Marshal(chatReq{
		Model: c.Cfg.Model,
		Messages: []chatMsg{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
	})
	url := strings.TrimRight(c.Cfg.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Cfg.APIKey)
	res, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	var out chatResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("ai decode: %w (%s)", err, truncate(string(raw), 200))
	}
	if out.Error != nil && out.Error.Message != "" {
		return "", fmt.Errorf("ai: %s", out.Error.Message)
	}
	if res.StatusCode >= 300 {
		return "", fmt.Errorf("ai http %d: %s", res.StatusCode, truncate(string(raw), 300))
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("ai: empty response")
	}
	return strings.TrimSpace(out.Choices[0].Message.Content), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
