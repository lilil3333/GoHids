package threatbook

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	API_URL = "https://api.threatbook.cn/v3/scene/ip_reputation"
)

type Client struct {
	APIKey string
	Cache  sync.Map // Simple in-memory cache to avoid rate limits
}

var (
	instance *Client
	once     sync.Once
)

// GetClient Singleton
func GetClient(apiKey string) *Client {
	once.Do(func() {
		instance = &Client{
			APIKey: apiKey,
		}
	})
	return instance
}

// IPReputationResponse matches the structure of ThreatBook API response
type IPReputationResponse struct {
	ResponseCode int                            `json:"response_code"`
	VerboseMsg   string                         `json:"verbose_msg"`
	Data         map[string]IPReputationDetails `json:"data"`
}

type IPReputationDetails struct {
	IsMalicious     bool     `json:"is_malicious"`
	Severity        string   `json:"severity"`
	ConfidenceLevel string   `json:"confidence_level"`
	Judgments       []string `json:"judgments"`
	TagsClasses     []struct {
		TagsType string      `json:"tags_type"`
		Tags     interface{} `json:"tags"` // Can be string or []string
	} `json:"tags_classes"`
	Basic struct {
		Location struct {
			Country  string `json:"country"`
			Province string `json:"province"`
			City     string `json:"city"`
		} `json:"location"`
		Carrier string `json:"carrier"`
	} `json:"basic"`
}

// QueryIPs queries multiple IPs (max 50 recommended for batch)
func (c *Client) QueryIPs(ips []string) (map[string]IPReputationDetails, error) {
	// Filter out cached or local IPs first
	var uniqueIPs []string
	results := make(map[string]IPReputationDetails)

	// Deduplicate
	seen := make(map[string]bool)
	for _, ip := range ips {
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true

		// Check cache
		if val, ok := c.Cache.Load(ip); ok {
			results[ip] = val.(IPReputationDetails)
		} else {
			uniqueIPs = append(uniqueIPs, ip)
		}
	}

	if len(uniqueIPs) == 0 {
		return results, nil
	}

	// Batch query logic (batch size 50)
	batchSize := 50
	for i := 0; i < len(uniqueIPs); i += batchSize {
		end := i + batchSize
		if end > len(uniqueIPs) {
			end = len(uniqueIPs)
		}
		batch := uniqueIPs[i:end]

		partialRes, err := c.doQuery(batch)
		if err != nil {
			fmt.Printf("[ThreatBook] Query error: %v\n", err)
			continue
		}

		for k, v := range partialRes {
			results[k] = v
			c.Cache.Store(k, v) // Update cache
		}

		// Rate limit sleep
		time.Sleep(200 * time.Millisecond)
	}

	return results, nil
}

func (c *Client) doQuery(ips []string) (map[string]IPReputationDetails, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	params := fmt.Sprintf("apikey=%s&resource=%s&lang=zh", c.APIKey, strings.Join(ips, ","))
	url := fmt.Sprintf("%s?%s", API_URL, params)

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResp IPReputationResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, err
	}

	if apiResp.ResponseCode != 0 {
		return nil, fmt.Errorf("API Error: %s", apiResp.VerboseMsg)
	}

	return apiResp.Data, nil
}
