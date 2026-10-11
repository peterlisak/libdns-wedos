package wedos

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestNormalizeZone(t *testing.T) {
	tests := []struct {
		name string
		zone string
		want string
	}{
		{name: "fully qualified zone", zone: "lisak.site.", want: "lisak.site"},
		{name: "already normalized zone", zone: "lisak.site", want: "lisak.site"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := normalizeZone(test.zone); got != test.want {
				t.Errorf("normalizeZone(%q) = %q, want %q", test.zone, got, test.want)
			}
		})
	}
}

func TestAppendRecordsCommitsZone(t *testing.T) {
	var commands []string
	var committedZone string
	provider := &Provider{
		Username: "user",
		Password: "password",
		httpClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(request.Body)
			if err != nil {
				return nil, err
			}
			form, err := url.ParseQuery(string(body))
			if err != nil {
				return nil, err
			}

			var envelope requestEnvelope
			if err := json.Unmarshal([]byte(form.Get("request")), &envelope); err != nil {
				return nil, err
			}
			commands = append(commands, envelope.Request.Command)
			if envelope.Request.Command == CommitDomain {
				var data map[string]string
				if err := json.Unmarshal(envelope.Request.Data, &data); err != nil {
					return nil, err
				}
				committedZone = data["name"]
			}

			responseBody := `{"response":{"code":1000,"result":"OK","command":"` + envelope.Request.Command + `","data":{"domain":"lisak.site","row_id":"123"}}}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(responseBody)),
			}, nil
		})},
	}

	added, err := provider.AppendRecords(context.Background(), "lisak.site.", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge.garden", Text: "challenge-token", TTL: 5 * time.Minute},
	})
	if err != nil {
		t.Fatalf("AppendRecords returned error: %v", err)
	}
	if len(added) != 1 {
		t.Fatalf("AppendRecords returned %d records, want 1", len(added))
	}
	if want := []string{AppendRecords, CommitDomain}; !equalStrings(commands, want) {
		t.Fatalf("WAPI command order = %v, want %v", commands, want)
	}
	if committedZone != "lisak.site" {
		t.Errorf("committed zone = %q, want %q", committedZone, "lisak.site")
	}
}

func TestSetRecordsCommitsSuccessfulChanges(t *testing.T) {
	tests := []struct {
		name string
		rows row
	}{
		{name: "append new record"},
		{name: "update existing record", rows: row{{ID: "123", Name: "_acme-challenge.test", Rdtype: TXTRecord}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var commands []string
			provider := newMockProvider(test.rows, &commands)
			_, err := provider.SetRecords(context.Background(), "lisak.site.", []libdns.Record{
				libdns.TXT{Name: "_acme-challenge.test", Text: "challenge-token", TTL: 5 * time.Minute},
			})
			if err != nil {
				t.Fatalf("SetRecords returned error: %v", err)
			}
			want := []string{GetRecords, AppendRecords, CommitDomain}
			if len(test.rows) > 0 {
				want = []string{GetRecords, UpdateRecords, CommitDomain}
			}
			if !equalStrings(commands, want) {
				t.Fatalf("WAPI command order = %v, want %v", commands, want)
			}
		})
	}
}

func TestDeleteRecordsCommitsSuccessfulDeletion(t *testing.T) {
	var commands []string
	provider := newMockProvider(row{{ID: "123", Name: "_acme-challenge.test", TTL: "300", Rdtype: TXTRecord, Rdata: "challenge-token"}}, &commands)
	_, err := provider.DeleteRecords(context.Background(), "lisak.site.", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge.test", Text: "challenge-token", TTL: 5 * time.Minute},
	})
	if err != nil {
		t.Fatalf("DeleteRecords returned error: %v", err)
	}
	if want := []string{GetRecords, DeleteRecords, CommitDomain}; !equalStrings(commands, want) {
		t.Fatalf("WAPI command order = %v, want %v", commands, want)
	}
}

func TestDeleteRecordsDoesNotCommitWithoutChanges(t *testing.T) {
	var commands []string
	provider := newMockProvider(nil, &commands)
	_, err := provider.DeleteRecords(context.Background(), "lisak.site.", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge.test", Text: "challenge-token", TTL: 5 * time.Minute},
	})
	if err != nil {
		t.Fatalf("DeleteRecords returned error: %v", err)
	}
	if want := []string{GetRecords}; !equalStrings(commands, want) {
		t.Fatalf("WAPI command order = %v, want %v", commands, want)
	}
}

func newMockProvider(rows row, commands *[]string) *Provider {
	return &Provider{
		Username: "user",
		Password: "password",
		httpClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(request.Body)
			if err != nil {
				return nil, err
			}
			form, err := url.ParseQuery(string(body))
			if err != nil {
				return nil, err
			}

			var envelope requestEnvelope
			if err := json.Unmarshal([]byte(form.Get("request")), &envelope); err != nil {
				return nil, err
			}
			*commands = append(*commands, envelope.Request.Command)

			var data json.RawMessage
			switch envelope.Request.Command {
			case GetRecords:
				data, err = json.Marshal(dnsRowsListResponse{Row: rows})
			case AppendRecords:
				data, err = json.Marshal(dnsAppendResponse{Domain: "lisak.site", ID: "123"})
			}
			if err != nil {
				return nil, err
			}

			responseBody, err := json.Marshal(responseEnvelope{Response: response{
				Code:    OK,
				Result:  "OK",
				Command: envelope.Request.Command,
				Data:    data,
			}})
			if err != nil {
				return nil, err
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(string(responseBody))),
			}, nil
		})},
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
