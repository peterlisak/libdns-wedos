// Package wedos implements a DNS record management client compatible
// with the libdns interfaces for WEDOS DNS.
package wedos

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/libdns/libdns"
)

const (
	GetRecords    = "dns-rows-list"
	AppendRecords = "dns-row-add"
	CommitDomain  = "dns-domain-commit"
	DeleteRecords = "dns-row-delete"
	UpdateRecords = "dns-row-update"
)

// Provider implements libdns for Wedos using the WAPI hour‑based SHA‑1 token.
type Provider struct {
	Username   string
	Password   string
	httpClient *http.Client
}

func normalizeZone(zone string) string {
	return strings.TrimSuffix(zone, ".")
}

func NewProvider(username, password string) *Provider {
	return &Provider{
		Username:   username,
		Password:   password,
		httpClient: &http.Client{},
	}
}

func (p *Provider) commitDomain(ctx context.Context, zone string) error {
	request, err := p.buildRequest(ctx, CommitDomain, "CommitDomain", map[string]string{
		"name": zone,
	})
	if err != nil {
		return err
	}

	response, err := p.doRequest(request)
	if err != nil {
		return err
	}

	envelope, err := p.parseResponse(response, nil)
	if err != nil {
		return err
	}
	if envelope.Response.Code != OK {
		return fmt.Errorf("commit domain: WEDOS returned code %d: %s", envelope.Response.Code, envelope.Response.Result)
	}

	return nil
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	zone = normalizeZone(zone)
	payload := map[string]string{
		"domain": zone,
	}

	request, err := p.buildRequest(ctx, GetRecords, "GetRecords", payload)
	if err != nil {
		return nil, err
	}

	response, err := p.doRequest(request)
	if err != nil {
		return nil, err
	}

	var data dnsRowsListResponse
	_, err = p.parseResponse(response, &data)
	if err != nil {
		return nil, err
	}

	var records []libdns.Record
	for _, row := range data.Row {
		record, err := toLibDNSRecord(row)
		if err != nil {
			return nil, err
		}

		records = append(records, record)
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zone = normalizeZone(zone)
	var addedRecords []libdns.Record

	for _, record := range records {
		payload, err := toWedosDNSRecord(record, zone)
		if err != nil {
			return nil, err
		}

		request, err := p.buildRequest(ctx, AppendRecords, "AppendRecords", payload)
		if err != nil {
			return nil, err
		}

		response, err := p.doRequest(request)
		if err != nil {
			return nil, err
		}

		var data dnsAppendResponse
		envelope, err := p.parseResponse(response, &data)
		if err != nil {
			return nil, err
		}

		if envelope.Response.Code == OK {
			addedRecords = append(addedRecords, record)
		}
	}

	if len(addedRecords) > 0 {
		if err := p.commitDomain(ctx, normalizeZone(zone)); err != nil {
			return addedRecords, err
		}
	}

	return addedRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zone = normalizeZone(zone)
	changed := false
	payload := map[string]string{
		"domain": zone,
	}

	request, err := p.buildRequest(ctx, GetRecords, "GetRecords", payload)
	if err != nil {
		return nil, err
	}
	response, err := p.doRequest(request)
	if err != nil {
		return nil, err
	}
	var remoteData dnsRowsListResponse
	_, err = p.parseResponse(response, &remoteData)
	if err != nil {
		return nil, err
	}

	remoteMap := make(map[recordKey]rowItem)
	for _, remoteRecord := range remoteData.Row {
		key := recordKey{
			Name: remoteRecord.Name,
			Type: remoteRecord.Rdtype,
			Data: "",
		}
		remoteMap[key] = remoteRecord
	}

	var updatedRecords []libdns.Record
	for _, recordToSet := range records {
		wedosRecordToSet, err := toWedosDNSRecord(recordToSet, zone)
		if err != nil {
			return nil, err
		}

		recordToSetKey := recordKey{
			Name: wedosRecordToSet["name"],
			Type: wedosRecordToSet["type"],
			Data: "",
		}

		_, ok := remoteMap[recordToSetKey]
		if !ok {
			payload := wedosRecordToSet
			request, err := p.buildRequest(ctx, AppendRecords, "AppendRecords", payload)
			if err != nil {
				return nil, err
			}

			response, err := p.doRequest(request)
			if err != nil {
				return nil, err
			}

			var data dnsAppendResponse
			envelope, err := p.parseResponse(response, &data)
			if err != nil {
				return nil, err
			}

			if envelope.Response.Code == OK {
				updatedRecords = append(updatedRecords, recordToSet)
				changed = true
			} else {
				// todo log error
				continue
			}
		} else {
			payload := map[string]string{
				"domain": zone,
				"row_id": remoteMap[recordToSetKey].ID,
				"ttl":    wedosRecordToSet["ttl"],
				"rdata":  wedosRecordToSet["rdata"],
			}

			request, err := p.buildRequest(ctx, UpdateRecords, "UpdateRecords", payload)
			if err != nil {
				return nil, err
			}

			response, err := p.doRequest(request)
			if err != nil {
				return nil, err
			}

			envelope, err := p.parseResponse(response, nil)
			if err != nil {
				return updatedRecords, err
			}
			if envelope.Response.Code != OK {
				return updatedRecords, fmt.Errorf("update record: WEDOS returned code %d: %s", envelope.Response.Code, envelope.Response.Result)
			}

			updatedRecords = append(updatedRecords, recordToSet)
			changed = true
		}
	}
	if changed {
		if err := p.commitDomain(ctx, zone); err != nil {
			return updatedRecords, err
		}
	}

	return updatedRecords, nil
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zone = normalizeZone(zone)
	changed := false
	payload := map[string]string{
		"domain": zone,
	}

	request, err := p.buildRequest(ctx, GetRecords, "GetRecords", payload)
	if err != nil {
		return nil, err
	}

	response, err := p.doRequest(request)
	if err != nil {
		return nil, err
	}

	var data dnsRowsListResponse
	_, err = p.parseResponse(response, &data)
	if err != nil {
		return nil, err
	}

	wanted := make(map[recordKey]libdns.Record, len(records))
	var deletedRecords []libdns.Record

	for _, rec := range records {
		wedosRec, err := toWedosDNSRecord(rec, zone)
		if err != nil {
			return nil, err
		}

		key := recordKey{
			Name: wedosRec["name"],
			Type: wedosRec["type"],
			Data: wedosRec["rdata"],
		}

		wanted[key] = rec
	}

	for _, row := range data.Row {
		key := recordKey{
			Name: row.Name,
			Type: row.Rdtype,
			Data: row.Rdata,
		}

		rec, ok := wanted[key]
		if !ok {
			continue
		}

		payload := map[string]string{
			"domain": zone,
			"row_id": row.ID,
		}

		req, err := p.buildRequest(ctx, DeleteRecords, "DeleteRecords", payload)
		if err != nil {
			return nil, err
		}

		resp, err := p.doRequest(req)
		if err != nil {
			return nil, err
		}

		env, err := p.parseResponse(resp, nil)
		if err != nil {
			return deletedRecords, err
		}
		if env.Response.Code != OK {
			return deletedRecords, fmt.Errorf("delete record: WEDOS returned code %d: %s", env.Response.Code, env.Response.Result)
		}

		delete(wanted, key)
		deletedRecords = append(deletedRecords, rec)
		changed = true
	}
	if changed {
		if err := p.commitDomain(ctx, zone); err != nil {
			return deletedRecords, err
		}
	}

	return deletedRecords, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
