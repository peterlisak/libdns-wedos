package wedos

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

const (
	ARecord       = "A"
	AAAARecord    = "AAAA"
	AliasRecord   = "ALIAS"
	CNAMERecord   = "CNAME"
	MXRecord      = "MX"
	TXTRecord     = "TXT"
	SRVRecord     = "SRV"
	NSRecord      = "NS"
	SORARRecord   = "SOA"
	DNAMERecord   = "DNAME"
	NAPROOTRecord = "NAPTR"
	CAARecord     = "CAA"
	HTTPSRecord   = "HTTPS"
	SSHFPRecord   = "SSHFP"
	TLSARecord    = "TLSA"
)

// normalizeNameFromAPI converts provider `name` into libdns-style Name (relative).
// zone must be canonicalized (no trailing dot, lower case).
func normalizeNameFromAPI(apiName string) (string, error) {
	apiName = strings.TrimSpace(apiName)
	if apiName == "" {
		return "@", nil
	}

	return apiName, nil
}

func normalizeNameToAPI(apiName string) (string, error) {
	apiName = strings.TrimSpace(apiName)
	if apiName == "@" {
		return "", nil
	}

	return apiName, nil
}

// toLibDNSRecord converts a rowItem (response from WEDOS API) into a libdns.Record
func toLibDNSRecord(row rowItem) (libdns.Record, error) {
	var record libdns.Record

	recordType := strings.ToUpper(strings.TrimSpace(row.Rdtype))
	ttlSeconds, err := strconv.Atoi(row.TTL)
	if err != nil {
		return nil, fmt.Errorf("toLibDNSRecord: failed to convert row.TTL (%s) to type int: %v", row.Rdata, err)
	}

	name, err := normalizeNameFromAPI(row.Name)
	if err != nil {
		return nil, err
	}

	switch recordType {
	case ARecord, AAAARecord:
		ip, err := netip.ParseAddr(strings.TrimSpace(row.Rdata))
		if err != nil {
			return nil, fmt.Errorf("invalid %s record value: %s: %w", recordType, row.Rdata, err)
		}
		record = libdns.Address{
			Name: name,
			IP:   ip,
			TTL:  time.Duration(ttlSeconds) * time.Second,
		}

	case CNAMERecord:
		record = libdns.CNAME{
			Name:   name,
			Target: strings.TrimSpace(row.Rdata),
			TTL:    time.Duration(ttlSeconds) * time.Second,
		}

	case TXTRecord:
		record = libdns.TXT{
			Name: name,
			Text: row.Rdata,
			TTL:  time.Duration(ttlSeconds) * time.Second,
		}

	case SRVRecord:
		service := strings.Split(row.Name, ".")
		serviceName := service[0][1:]
		serviceProtocol := service[1][1:]
		serviceSubdomain := service[2]

		parts := strings.Split(row.Rdata, " ")
		if len(parts) != 4 {
			return nil, fmt.Errorf("toLibDNSRecord: invalid SRV record value: %s", row.Rdata)
		}

		priority, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("toLibDNSRecord: invalid SRV record value: %s: %w", row.Rdata, err)
		}

		weight, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("toLibDNSRecord: invalid SRV record value: %s: %w", row.Rdata, err)
		}

		port, err := strconv.Atoi(parts[2])
		if err != nil {
			return nil, fmt.Errorf("toLibDNSRecord: invalid SRV record value: %s: %w", row.Rdata, err)
		}

		hostname := parts[3]

		record = libdns.SRV{
			Service:   serviceName,
			Transport: serviceProtocol,
			Name:      serviceSubdomain, // todo "_minecraft._tcp.mc" or "mc"?
			TTL:       time.Duration(ttlSeconds) * time.Second,
			Priority:  uint16(priority),
			Weight:    uint16(weight),
			Port:      uint16(port),
			Target:    hostname,
		}

	default:
		// Generic RR fallback
		record = libdns.RR{
			Name: name,
			TTL:  time.Duration(ttlSeconds) * time.Second,
			Type: row.Rdtype,
			Data: row.Rdata,
		}
	}

	return record, nil
}

// toWedosDNSRecord converts a libdns.Record to a JSON format represented by a map for the WEDOS API
func toWedosDNSRecord(record libdns.Record, zone string) (map[string]string, error) {
	zone = strings.TrimSuffix(zone, ".")
	name, err := normalizeNameToAPI(record.RR().Name)
	if err != nil {
		return nil, fmt.Errorf("toWedosDNSRecord: failed to normalize name: %v", err)
	}

	switch r := record.(type) {
	case libdns.Address:
		recordType := ARecord
		if r.IP.Is6() {
			recordType = AAAARecord
		}
		return map[string]string{
			"domain": zone,
			"name":   name,
			"ttl":    strconv.Itoa(int(r.TTL.Seconds())),
			"type":   recordType,
			"rdata":  r.IP.String(),
		}, nil

	case libdns.CNAME:
		return map[string]string{
			"domain": zone,
			"name":   name,
			"ttl":    strconv.Itoa(int(r.TTL.Seconds())),
			"type":   CNAMERecord,
			"rdata":  r.Target,
		}, nil
	case libdns.TXT:
		p := map[string]string{
			"domain": zone,
			"name":   name,
			"ttl":    strconv.Itoa(int(r.TTL.Seconds())),
			"type":   TXTRecord,
			"rdata":  r.Text,
		}
		return p, nil
	case libdns.MX:
		return map[string]string{
			"domain": zone,
			"name":   name,
			"ttl":    strconv.Itoa(int(r.TTL.Seconds())),
			"type":   MXRecord,
			"rdata":  fmt.Sprintf("%d %s", r.Preference, r.Target),
		}, nil
	case libdns.NS:
		return map[string]string{
			"domain": zone,
			"name":   name,
			"ttl":    strconv.Itoa(int(r.TTL.Seconds())),
			"type":   NSRecord,
			"rdata":  r.Target,
		}, nil
	case libdns.SRV:
		return map[string]string{
			"domain": zone,
			"name":   name,
			"ttl":    strconv.Itoa(int(r.TTL.Seconds())),
			"type":   SRVRecord,
			"rdata":  fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, r.Target),
		}, nil
	case libdns.RR:
		return map[string]string{
			"domain": zone,
			"name":   name,
			"ttl":    strconv.Itoa(int(r.TTL.Seconds())),
			"type":   r.Type,
			"rdata":  r.Data,
		}, nil
	default:
		rr := record.RR()
		return map[string]string{
			"domain": zone,
			"name":   name,
			"ttl":    strconv.Itoa(int(rr.TTL.Seconds())),
			"type":   rr.Type,
			"rdata":  rr.Data,
		}, nil
	}
}
