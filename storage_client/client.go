package storage_client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type ListObjectsResponse struct {
	Folders []string `json:"folders"`
	Files   []string `json:"files"`
}

func (c *Client) ListObjects(prefix string, delimiter string) (*ListObjectsResponse, error) {
	reqURL := fmt.Sprintf("%s/api/v1/list?prefix=%s&delimiter=%s", c.BaseURL, url.QueryEscape(prefix), url.QueryEscape(delimiter))
	resp, err := c.HTTPClient.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("failed to call storage service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("storage service returned status %d: %s", resp.StatusCode, string(body))
	}

	var result ListObjectsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response from storage service: %w", err)
	}

	return &result, nil
}

func (c *Client) ListAllFolders() ([]string, error) {
	reqURL := fmt.Sprintf("%s/api/v1/list-all-folders", c.BaseURL)
	resp, err := c.HTTPClient.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("failed to call storage service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("storage service returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Folders []string `json:"folders"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response from storage service: %w", err)
	}
	return result.Folders, nil
}

func (c *Client) GeneratePresignedURL(objectKey string, expires int64) (string, error) {
	reqURL := fmt.Sprintf("%s/api/v1/generate-url?objectKey=%s&expires=%d", c.BaseURL, url.QueryEscape(objectKey), expires)
	resp, err := c.HTTPClient.Get(reqURL)
	if err != nil {
		return "", fmt.Errorf("failed to call storage service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("storage service returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response from storage service: %w", err)
	}

	return result.URL, nil
}

func (c *Client) GetArchive(keys []string, folders []string) (*http.Response, error) {
	reqURL := fmt.Sprintf("%s/api/v1/archive", c.BaseURL)

	body, err := json.Marshal(map[string][]string{
		"keys":    keys,
		"folders": folders,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal archive request body: %w", err)
	}

	req, err := http.NewRequest("POST", reqURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create archive request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Use a client with a longer timeout for potentially large archives
	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call storage service for archive: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		defer resp.Body.Close()
		return nil, fmt.Errorf("storage service returned status %d for archive: %s", resp.StatusCode, string(respBody))
	}

	return resp, nil
}
