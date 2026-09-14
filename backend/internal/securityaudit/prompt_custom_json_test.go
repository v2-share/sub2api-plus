package securityaudit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseCustomJSONUsesConfidenceAsFlagWhenFlaggedIsOmitted(t *testing.T) {
	result, err := ParseCustomJSON(`{"confidence":0.75,"reason":"针对他人系统攻击"}`)
	require.NoError(t, err)
	require.Equal(t, EventCritical, result.Decision)
	require.Equal(t, RiskCritical, result.RiskLevel)
	require.Equal(t, ActionBlock, result.Action)
	require.Equal(t, 0.75, result.Confidence)
	require.Equal(t, "针对他人系统攻击", result.Reason)
	require.Equal(t, []string{CustomPolicyCategory}, result.Categories)
	require.Equal(t, []string{CustomPolicyCategory}, result.MatchedScanners)
	require.Equal(t, 0.75, result.ScannerScores[CustomPolicyCategory])
	require.Equal(t, "针对他人系统攻击", result.ScannerEvidence[CustomPolicyCategory])
}

func TestParseCustomJSONAllowsLowConfidenceAndHonorsLegacyFlaggedField(t *testing.T) {
	safe, err := ParseCustomJSON(`{"confidence":0.05,"reason":""}`)
	require.NoError(t, err)
	require.Equal(t, EventPass, safe.Decision)
	require.Equal(t, ActionAllow, safe.Action)
	require.Empty(t, safe.Categories)

	flagged, err := ParseCustomJSON(`{"flagged":true,"confidence":0.25,"reason":"明确违规"}`)
	require.NoError(t, err)
	require.Equal(t, EventCritical, flagged.Decision)
	require.Equal(t, ActionBlock, flagged.Action)
	require.Equal(t, 0.25, flagged.Confidence)
}

func TestAggregateCustomJSONKeepsHighestConfidenceAndReason(t *testing.T) {
	first, err := ParseCustomJSON(`{"confidence":0.2,"reason":"边界不确定"}`)
	require.NoError(t, err)
	first.GuardEndpointID = "custom-one"
	second, err := ParseCustomJSON(`{"confidence":0.9,"reason":"攻击他人系统"}`)
	require.NoError(t, err)
	second.GuardEndpointID = "custom-two"

	result, err := AggregateResults([]*NormalizedResult{first, second}, 12*time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, 0.9, result.Confidence)
	require.Equal(t, "攻击他人系统", result.Reason)
	require.Equal(t, "custom-two", result.GuardEndpointID)
	require.Equal(t, "custom_policy", result.MatchedScanners[0])
	require.Equal(t, 12, result.LatencyMS)
}

func TestParseCustomJSONRejectsInvalidResponses(t *testing.T) {
	cases := []string{
		`{}`,
		`{"confidence":-0.1,"reason":"bad"}`,
		`{"confidence":1.1,"reason":"bad"}`,
		`{"confidence":0.1,"reason":"这是一段超过二十个 Unicode 字符的理由"}`,
		`{"confidence":0.1,"reason":"ok","extra":true}`,
		`{"confidence":0.1,"reason":"ok"} trailing`,
	}
	for _, raw := range cases {
		_, err := ParseCustomJSON(raw)
		require.Error(t, err, raw)
	}
}

func TestCustomJSONScannerSendsConfiguredSystemPromptAndWrappedInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/chat/completions", r.URL.Path)
		var payload struct {
			Model    string `json:"model"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
			Temperature float64 `json:"temperature"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		require.Equal(t, "deepseek-v4-flash", payload.Model)
		require.Len(t, payload.Messages, 2)
		require.Equal(t, "system", payload.Messages[0].Role)
		require.Equal(t, "system-canary", payload.Messages[0].Content)
		require.Equal(t, "user", payload.Messages[1].Role)
		require.Contains(t, payload.Messages[1].Content, "<user_input>\nhello\n</user_input>")
		require.Contains(t, payload.Messages[1].Content, `{"confidence": 0.00, "reason": "..."}`)
		require.Equal(t, float64(0), payload.Temperature)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"confidence\":0.9,\"reason\":\"攻击他人系统\"}"}}]}`))
	}))
	defer server.Close()

	result, err := NewOpenAICompatibleScanner().Scan(context.Background(), ActiveEndpoint{
		ID: "custom", BaseURL: server.URL, Model: "deepseek-v4-flash", EngineMode: EngineModeCustomJSON,
		SystemPrompt: "system-canary", TimeoutMS: 1000,
	}, "hello", AllScannerIDs)
	require.NoError(t, err)
	require.Equal(t, EventCritical, result.Decision)
	require.Equal(t, "custom-json-openai", result.ScannerBackend)
}

func TestPromptAuditConfigDefaultsToQwenAndUpdatedSystemPrompt(t *testing.T) {
	storage, err := ParseStorageConfig("")
	require.NoError(t, err)
	require.Equal(t, EngineModeQwen3Guard, storage.EngineMode)
	require.Equal(t, DefaultSystemPrompt, storage.SystemPrompt)
	require.Contains(t, storage.SystemPrompt, "持有完整源码即按自有工程处理")

	legacy, err := ParseStorageConfig(`{"enabled":false,"config_version":3}`)
	require.NoError(t, err)
	require.Equal(t, EngineModeQwen3Guard, legacy.EngineMode)
	require.Equal(t, DefaultSystemPrompt, legacy.SystemPrompt)
	require.NotContains(t, strings.ToLower(legacy.SystemPrompt), "placeholder")
}
