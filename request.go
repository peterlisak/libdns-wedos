package wedos

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	BaseURL        = "https://api.wedos.com/wapi/json"
	PragueTimezone = "Europe/Prague"
	TimezoneOffset = 1 * 60 * 60
)

// getCurrentTime returns current time in a specified timezone.
// Offset is used if the timezone cannot be automatically determined.
func getCurrentTime(timezone string, offset int) time.Time {
	location, err := time.LoadLocation(timezone)
	if err != nil {
		location = time.FixedZone(timezone, offset)
	}

	return time.Now().In(location)
}

// createAuthString returns an authentification string used for API requests.
func (p *Provider) createAuthString() string {
	timeInPrague := getCurrentTime(PragueTimezone, TimezoneOffset)
	hour := timeInPrague.Hour()

	passwordHash := sha1.Sum([]byte(p.Password))
	passwordHashString := hex.EncodeToString(passwordHash[:])

	concat := fmt.Sprintf("%s%s%d", p.Username, passwordHashString, hour)
	authHash := sha1.Sum([]byte(concat))

	return hex.EncodeToString(authHash[:])
}

// buildRequest creates an HTTP POST request for the Wedos API with the specified command, transaction ID, and payload.
func (p *Provider) buildRequest(ctx context.Context, command string, clTRID string, payload any) (req *http.Request, err error) {
	if p.Username == "" || p.Password == "" {
		err = fmt.Errorf("buildRequest: missing username and/or password")
		return
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodPost, BaseURL, nil)
	if err != nil {
		err = fmt.Errorf("buildRequest: failed to create req: %v", err)
		return
	}

	requestBody := request{
		User:    p.Username,
		Auth:    p.createAuthString(),
		Command: command,
		ClTRID:  clTRID,
	}

	if payload != nil {
		rawPayload, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("buildRequest: failed to marshal payload: %v", err)
		}
		requestBody.Data = rawPayload
	}

	requestEnvelope := requestEnvelope{
		Request: requestBody,
	}

	requestJSON, err := json.Marshal(requestEnvelope)
	if err != nil {
		return nil, fmt.Errorf("buildRequest: failed to marshal req: %v", err)
	}

	requestWrapped := map[string]string{
		"request": string(requestJSON),
	}

	form := url.Values{}
	for k, v := range requestWrapped {
		form.Set(k, v)
	}

	requestEncoded := strings.NewReader(form.Encode())

	req.Body = io.NopCloser(requestEncoded)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}

// doRequest performs an HTTP request using the provided http.Request and returns the response or an error.
func (p *Provider) doRequest(request *http.Request) (response *http.Response, err error) {
	var client *http.Client
	if p.httpClient != nil {
		client = p.httpClient
	} else {
		client = &http.Client{}
	}

	p.logRequest(request)

	response, err = client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("doRequest: failed to do request: %v", err)
	}

	p.logResponse(response)

	return response, nil
}

func (p *Provider) logRequest(request *http.Request) {
	if !debugHTTPEnabled() || request.Body == nil {
		return
	}

	body, err := io.ReadAll(request.Body)
	if err != nil {
		log.Printf("wedos HTTP request: method=%s url=%s body_read_error=%v", request.Method, request.URL, err)
		return
	}
	request.Body = io.NopCloser(strings.NewReader(string(body)))

	form, err := url.ParseQuery(string(body))
	if err != nil {
		log.Printf("wedos HTTP request: method=%s url=%s form_parse_error=%v", request.Method, request.URL, err)
		return
	}

	var envelope requestEnvelope
	if err := json.Unmarshal([]byte(form.Get("request")), &envelope); err != nil {
		log.Printf("wedos HTTP request: method=%s url=%s request_parse_error=%v", request.Method, request.URL, err)
		return
	}

	envelope.Request.Auth = "REDACTED"
	redacted, err := json.Marshal(envelope)
	if err != nil {
		log.Printf("wedos HTTP request: method=%s url=%s redact_error=%v", request.Method, request.URL, err)
		return
	}

	log.Printf("wedos HTTP request: method=%s url=%s body=%s", request.Method, request.URL, redacted)
}

func (p *Provider) logResponse(response *http.Response) {
	if !debugHTTPEnabled() || response.Body == nil {
		return
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Printf("wedos HTTP response: status=%s body_read_error=%v", response.Status, err)
		return
	}
	response.Body = io.NopCloser(strings.NewReader(string(body)))

	log.Printf("wedos HTTP response: status=%s body=%s", response.Status, body)
}

func debugHTTPEnabled() bool {
	return strings.EqualFold(os.Getenv("WEDOS_DEBUG_HTTP"), "true")
}
