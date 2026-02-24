package reconnaissance

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// DNS record type constants (RFC 1035 and extensions)
const (
	dnsTypeA      uint16 = 1
	dnsTypeNS     uint16 = 2
	dnsTypeCNAME  uint16 = 5
	dnsTypeSOA    uint16 = 6
	dnsTypePTR    uint16 = 12
	dnsTypeHINFO  uint16 = 13
	dnsTypeMX     uint16 = 15
	dnsTypeTXT    uint16 = 16
	dnsTypeLOC    uint16 = 29
	dnsTypeAAAA   uint16 = 28
	dnsTypeSRV    uint16 = 33
	dnsTypeDS     uint16 = 43
	dnsTypeDNSKEY uint16 = 48
	dnsTypeCAA    uint16 = 257
)

// Default DNS resolvers (host:port; IPv6 in [host]:port form so all resolvers are used)
var dnsRecordResolvers = []string{
	"1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53", "8.8.4.4:53",
	"9.9.9.9:53", "149.112.112.112:53", "208.67.222.222:53", "208.67.220.220:53",
	"84.200.69.80:53", "84.200.70.40:53", "[2001:4860:4860::8888]:53", "[2001:4860:4860::8844]:53",
	"213.196.191.96:53", "149.112.112.9:53",
}

const dnsFlagRD uint16 = 1 << 8

// DnsRecords queries multiple DNS servers for various DNS record types for a given URL or IP address.
// Uses only Go standard library. Records are printed unduplicated.
// If wg is not nil, the caller is responsible for calling Done().
func DnsRecords(input string, wg *sync.WaitGroup) {
	URL := strings.TrimSpace(input)
	isIP := net.ParseIP(URL) != nil

	if isIP {
		fmt.Printf("\nDetected IP address input: %s\n", input)
		fmt.Printf("Performing only PTR lookup for IP addresses\n\n")
		performPTRLookupNative(URL)
		return
	}

	fmt.Printf("\nDNS Records for %s:\n", URL)
	fmt.Printf("====================\n")

	// Deduplicated record sets per type (key -> true)
	recordSets := map[uint16]map[string]bool{
		dnsTypeA:      make(map[string]bool),
		dnsTypeAAAA:   make(map[string]bool),
		dnsTypeCNAME:  make(map[string]bool),
		dnsTypeMX:     make(map[string]bool),
		dnsTypeNS:     make(map[string]bool),
		dnsTypeTXT:    make(map[string]bool),
		dnsTypeSOA:    make(map[string]bool),
		dnsTypeHINFO:  make(map[string]bool),
		dnsTypeSRV:    make(map[string]bool),
		dnsTypeCAA:    make(map[string]bool),
		dnsTypeLOC:    make(map[string]bool),
		dnsTypeDS:     make(map[string]bool),
		dnsTypeDNSKEY: make(map[string]bool),
	}
	ipSet := make(map[string]bool)
	var mu sync.Mutex

	recordTypes := []uint16{
		dnsTypeA, dnsTypeAAAA, dnsTypeCNAME, dnsTypeMX, dnsTypeNS, dnsTypeTXT,
		dnsTypeSOA, dnsTypeHINFO, dnsTypeSRV, dnsTypeCAA, dnsTypeLOC, dnsTypeDS, dnsTypeDNSKEY,
	}

	var queryWg sync.WaitGroup
	for _, rt := range recordTypes {
		for _, resolver := range dnsRecordResolvers {
			queryWg.Add(1)
			go func(recordType uint16, res string) {
				defer queryWg.Done()
				resp, err := sendDNSQuery(URL, recordType, res)
				if err != nil {
					return
				}
				// Harvest all record types from this response (Answer + Authority + Additional)
				allRecords, ips := parseDNSResponseAll(resp)
				mu.Lock()
				for typ, keys := range allRecords {
					if set, ok := recordSets[typ]; ok {
						for _, k := range keys {
							if k != "" {
								set[k] = true
								// Ensure PTR has IPs: A/AAAA keys are the IP strings
								if typ == dnsTypeA || typ == dnsTypeAAAA {
									ipSet[k] = true
								}
							}
						}
					}
				}
				for _, ip := range ips {
					ipSet[ip] = true
				}
				mu.Unlock()
			}(rt, resolver)
		}
	}
	queryWg.Wait()

	// Print unduplicated
	printRecordSet("A Records", recordSets[dnsTypeA], nil)
	printRecordSet("AAAA Records", recordSets[dnsTypeAAAA], nil)
	printRecordSet("CNAME Records", recordSets[dnsTypeCNAME], nil)
	printRecordSet("MX Records", recordSets[dnsTypeMX], formatMXWithTTL)
	printRecordSet("NS Records", recordSets[dnsTypeNS], nil)
	printRecordSet("TXT Records", recordSets[dnsTypeTXT], formatTXTWithTTL)
	printRecordSet("SOA Records", recordSets[dnsTypeSOA], formatSOA)
	printRecordSet("HINFO Records", recordSets[dnsTypeHINFO], formatHINFO)
	printRecordSet("SRV Records", recordSets[dnsTypeSRV], formatSRV)
	printRecordSet("CAA Records", recordSets[dnsTypeCAA], formatCAA)
	printRecordSet("LOC Records", recordSets[dnsTypeLOC], formatLOC)
	printRecordSet("DS Records", recordSets[dnsTypeDS], formatDS)
	printRecordSet("DNSKEY Records", recordSets[dnsTypeDNSKEY], formatDNSKEY)

	// PTR for discovered IPs
	if len(ipSet) > 0 {
		fmt.Println("\nPTR Records:")
		ptrSeen := make(map[string]bool)
		var ptrMu sync.Mutex
		var ptrWg sync.WaitGroup
		for ip := range ipSet {
			ptrWg.Add(1)
			go func(ipAddr string) {
				defer ptrWg.Done()
				for _, res := range dnsRecordResolvers {
					ptr, err := queryPTRNative(ipAddr, res)
					if err != nil || ptr == "" {
						continue
					}
					ptrMu.Lock()
					if !ptrSeen[ipAddr] {
						ptrSeen[ipAddr] = true
						fmt.Printf("- %s -> %s\n", ipAddr, ptr)
					}
					ptrMu.Unlock()
					return
				}
			}(ip)
		}
		ptrWg.Wait()
		if len(ptrSeen) == 0 {
			fmt.Println("- No PTR records found")
		}
	}
}

// createDNSQuery builds a DNS query message (standard library only).
func createDNSQuery(domain string, qtype uint16) []byte {
	// Header: ID, Flags, QdCount=1, AnCount=0, NsCount=0, ArCount=0
	id := uint16(time.Now().UnixNano() % 65536)
	msg := make([]byte, 0, 512)
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, id)
	msg = append(msg, buf...)
	binary.BigEndian.PutUint16(buf, dnsFlagRD)
	msg = append(msg, buf...)
	binary.BigEndian.PutUint16(buf, 1)
	msg = append(msg, buf...)
	msg = append(msg, 0, 0, 0, 0, 0, 0)
	// Question: name (DNS-encoded), type, class IN
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if len(part) > 0 {
			msg = append(msg, byte(len(part)))
			msg = append(msg, []byte(part)...)
		}
	}
	msg = append(msg, 0)
	binary.BigEndian.PutUint16(buf, qtype)
	msg = append(msg, buf...)
	binary.BigEndian.PutUint16(buf, 1) // Class IN
	msg = append(msg, buf...)
	return msg
}

const dnsQueryRetries = 2

func sendDNSQuery(domain string, qtype uint16, resolver string) ([]byte, error) {
	query := createDNSQuery(domain, qtype)
	var lastErr error
	for attempt := 0; attempt <= dnsQueryRetries; attempt++ {
		conn, err := net.DialTimeout("udp", resolver, 5*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(query); err != nil {
			conn.Close()
			lastErr = err
			continue
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if n >= 12 {
			return buf[:n], nil
		}
		lastErr = fmt.Errorf("response too short")
		if attempt < dnsQueryRetries {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return nil, lastErr
}

// wantTypes is the set of DNS record types we collect (for parseDNSResponseAll and PTR responses).
var wantTypes = map[uint16]bool{
	dnsTypeA: true, dnsTypeAAAA: true, dnsTypeCNAME: true, dnsTypeMX: true,
	dnsTypeNS: true, dnsTypeTXT: true, dnsTypeSOA: true, dnsTypeHINFO: true,
	dnsTypeSRV: true, dnsTypeCAA: true, dnsTypeLOC: true, dnsTypeDS: true, dnsTypeDNSKEY: true,
	dnsTypePTR: true, // needed so parseDNSResponse(resp, dnsTypePTR) returns PTR keys
}

// parseDNSResponseAll parses the response and returns all RRs by type (Answer + Authority + Additional)
// so that one response (e.g. A query) contributes CNAME, NS, etc. when present. IPs collected for PTR.
func parseDNSResponseAll(resp []byte) (allRecords map[uint16][]string, ips []string) {
	allRecords = make(map[uint16][]string)
	if len(resp) < 12 {
		return allRecords, nil
	}
	anCount := binary.BigEndian.Uint16(resp[6:8])
	nsCount := binary.BigEndian.Uint16(resp[8:10])
	arCount := binary.BigEndian.Uint16(resp[10:12])
	flags := binary.BigEndian.Uint16(resp[2:4])
	if (flags & 0x8000) == 0 {
		return allRecords, nil
	}
	// Still parse and harvest when rcode != 0 (e.g. authority section may have NS/SOA)
	offset := 12
	qdCount := binary.BigEndian.Uint16(resp[4:6])
	for i := 0; i < int(qdCount); i++ {
		offset = skipDNSName(resp, offset)
		if offset < 0 || offset+4 > len(resp) {
			return allRecords, nil
		}
		offset += 4
	}
	total := int(anCount + nsCount + arCount)
	for i := 0; i < total && offset < len(resp); i++ {
		start := offset
		offset = skipDNSName(resp, offset)
		if offset < 0 || offset+10 > len(resp) {
			break
		}
		typ := binary.BigEndian.Uint16(resp[offset : offset+2])
		offset += 2
		offset += 2 // class
		ttl := binary.BigEndian.Uint32(resp[offset : offset+4])
		offset += 4
		if offset+2 > len(resp) {
			break
		}
		rdLen := binary.BigEndian.Uint16(resp[offset : offset+2])
		offset += 2
		if offset+int(rdLen) > len(resp) {
			break
		}
		rdataStart := offset
		rdata := resp[offset : offset+int(rdLen)]
		offset += int(rdLen)
		if !wantTypes[typ] {
			continue
		}
		key := decodeRecordKey(resp, typ, rdata, start, rdataStart)
		if key != "" {
			if typ == dnsTypeMX || typ == dnsTypeTXT {
				key = fmt.Sprintf("%d|%s", ttl, key)
			}
			allRecords[typ] = append(allRecords[typ], key)
		}
		if typ == dnsTypeA && len(rdata) >= 4 {
			ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", rdata[0], rdata[1], rdata[2], rdata[3]))
		} else if typ == dnsTypeAAAA && len(rdata) >= 16 {
			ips = append(ips, net.IP(rdata[:16]).String())
		}
	}
	return allRecords, ips
}

// parseDNSResponse parses response and returns keys for the requested record type and IPs (used for PTR).
func parseDNSResponse(resp []byte, wantType uint16) (keys []string, ips []string) {
	all, ips := parseDNSResponseAll(resp)
	return all[wantType], ips
}

func decodeRecordKey(msg []byte, typ uint16, rdata []byte, _, rdataStart int) string {
	switch typ {
	case dnsTypeA:
		if len(rdata) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", rdata[0], rdata[1], rdata[2], rdata[3])
		}
	case dnsTypeAAAA:
		if len(rdata) >= 16 {
			return net.IP(rdata[:16]).String()
		}
	case dnsTypeCNAME, dnsTypeNS, dnsTypePTR:
		target, err := decodeDNSName(msg, rdataStart)
		if err != nil {
			return ""
		}
		return target
	case dnsTypeMX:
		if len(rdata) >= 2 {
			pref := binary.BigEndian.Uint16(rdata[:2])
			mx, err := decodeDNSName(msg, rdataStart+2)
			if err != nil {
				return ""
			}
			return fmt.Sprintf("%d %s", pref, mx)
		}
	case dnsTypeTXT:
		var parts []string
		o := 0
		for o < len(rdata) {
			if o+1 > len(rdata) {
				break
			}
			l := int(rdata[o])
			o++
			if l == 0 {
				continue
			}
			if o+l > len(rdata) {
				// Truncated or malformed: use what we have
				if o < len(rdata) {
					parts = append(parts, string(rdata[o:]))
				}
				break
			}
			parts = append(parts, string(rdata[o:o+l]))
			o += l
		}
		s := strings.Join(parts, " ")
		if s != "" {
			return s
		}
		return ""
	case dnsTypeSOA:
		mname, err := decodeDNSName(msg, rdataStart)
		if err != nil {
			return ""
		}
		next := skipDNSName(msg, rdataStart)
		if next < 0 {
			return ""
		}
		rname, err := decodeDNSName(msg, next)
		if err != nil {
			return ""
		}
		next = skipDNSName(msg, next)
		if next < 0 || next+20 > len(msg) || next+20 > rdataStart+len(rdata) {
			return ""
		}
		serial := binary.BigEndian.Uint32(msg[next:])
		refresh := binary.BigEndian.Uint32(msg[next+4:])
		retry := binary.BigEndian.Uint32(msg[next+8:])
		expire := binary.BigEndian.Uint32(msg[next+12:])
		minTtl := binary.BigEndian.Uint32(msg[next+16:])
		return fmt.Sprintf("%s %s %d %d %d %d %d", mname, rname, serial, refresh, retry, expire, minTtl)
	case dnsTypeHINFO:
		if len(rdata) < 2 {
			return ""
		}
		cl := int(rdata[0])
		if 1+cl >= len(rdata) {
			return ""
		}
		cpu := string(rdata[1 : 1+cl])
		o := 1 + cl
		if o >= len(rdata) {
			return cpu + " "
		}
		ol := int(rdata[o])
		o++
		if o+ol > len(rdata) {
			return cpu + " "
		}
		os := string(rdata[o : o+ol])
		return cpu + " " + os
	case dnsTypeSRV:
		if len(rdata) < 6 {
			return ""
		}
		prio := binary.BigEndian.Uint16(rdata[0:2])
		weight := binary.BigEndian.Uint16(rdata[2:4])
		port := binary.BigEndian.Uint16(rdata[4:6])
		target, err := decodeDNSName(msg, rdataStart+6)
		if err != nil {
			return ""
		}
		return fmt.Sprintf("%s %d %d %d", target, port, prio, weight)
	case dnsTypeCAA:
		if len(rdata) < 2 {
			return ""
		}
		flag := rdata[0]
		pos := 1
		tagLen := int(rdata[1])
		pos += 1 + tagLen
		if pos > len(rdata) {
			return ""
		}
		tag := string(rdata[2 : 2+tagLen])
		value := string(rdata[pos:])
		return fmt.Sprintf("%d %s %s", flag, tag, value)
	case dnsTypeLOC:
		if len(rdata) < 16 {
			return ""
		}
		// RFC 1876: version(1), size(1), horiz(1), vert(1), latitude(4), longitude(4), altitude(4)
		lat := decodeLOCCoord(rdata[4:8])
		lon := decodeLOCCoord(rdata[8:12])
		alt := decodeLOCAlt(rdata[12:16])
		size := float64(rdata[1]) / 100.0
		horiz := float64(rdata[2]) / 100.0
		vert := float64(rdata[3]) / 100.0
		return fmt.Sprintf("%.6f %.6f %.6f %f %f %f", lat, lon, alt, size, horiz, vert)
	case dnsTypeDS:
		if len(rdata) < 4 {
			return ""
		}
		keyTag := binary.BigEndian.Uint16(rdata[0:2])
		algo := rdata[2]
		digestType := rdata[3]
		digest := fmt.Sprintf("%x", rdata[4:])
		return fmt.Sprintf("%d %d %d %s", keyTag, algo, digestType, digest)
	case dnsTypeDNSKEY:
		if len(rdata) < 4 {
			return ""
		}
		flags := binary.BigEndian.Uint16(rdata[0:2])
		algorithm := rdata[3]
		pubKey := fmt.Sprintf("%x", rdata[4:])
		keyTag := calcDNSKEYKeyTag(rdata)
		return fmt.Sprintf("%d %d %d %s", keyTag, algorithm, flags, pubKey)
	}
	return ""
}

func decodeLOCCoord(b []byte) float64 {
	if len(b) < 4 {
		return 0
	}
	d := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return float64(int32(d)) / 3600000.0
}

func decodeLOCAlt(b []byte) float64 {
	if len(b) < 4 {
		return 0
	}
	d := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return float64(int32(d)) / 100.0
}

func calcDNSKEYKeyTag(rdata []byte) uint16 {
	if len(rdata) < 4 {
		return 0
	}
	// RFC 4034 key tag calculation (simplified for algorithm 5/7/8 common case)
	ac := uint32(0)
	for i := 0; i < len(rdata); i += 2 {
		if i+1 < len(rdata) {
			ac += uint32(rdata[i])<<8 | uint32(rdata[i+1])
		} else {
			ac += uint32(rdata[i]) << 8
		}
	}
	ac += (ac >> 16) & 0xFFFF
	return uint16(ac & 0xFFFF)
}

// reverseAddr returns the in-addr.arpa or ip6.arpa name for PTR lookup.
func reverseAddr(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP")
	}
	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", ip4[3], ip4[2], ip4[1], ip4[0]), nil
	}
	// IPv6: each nibble (LSB first) as a label, then .ip6.arpa.
	ip16 := ip.To16()
	if ip16 == nil {
		return "", fmt.Errorf("invalid IP")
	}
	const hex = "0123456789abcdef"
	buf := make([]byte, 0, 72)
	for i := len(ip16) - 1; i >= 0; i-- {
		buf = append(buf, hex[ip16[i]&0xF], '.', hex[ip16[i]>>4], '.')
	}
	return string(buf) + "ip6.arpa.", nil
}

func queryPTRNative(ipAddr, resolver string) (string, error) {
	rev, err := reverseAddr(ipAddr)
	if err != nil {
		return "", err
	}
	resp, err := sendDNSQuery(rev, dnsTypePTR, resolver)
	if err != nil {
		return "", err
	}
	keys, _ := parseDNSResponse(resp, dnsTypePTR)
	if len(keys) > 0 {
		return keys[0], nil
	}
	return "", fmt.Errorf("no PTR record")
}

func performPTRLookupNative(ip string) {
	fmt.Println("PTR Records:")
	found := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, res := range dnsRecordResolvers {
		wg.Add(1)
		go func(resolver string) {
			defer wg.Done()
			ptr, err := queryPTRNative(ip, resolver)
			if err != nil {
				return
			}
			mu.Lock()
			if !found[ptr] {
				found[ptr] = true
				fmt.Printf("- %s -> %s\n", ip, ptr)
			}
			mu.Unlock()
		}(res)
	}
	wg.Wait()
	if len(found) == 0 {
		fmt.Println("- No PTR records found for this IP address")
	}
}

// printRecordSet prints a deduplicated record set with optional formatter.
func printRecordSet(title string, records map[string]bool, formatter func(string) string) {
	fmt.Printf("\n%s:\n", title)
	if len(records) == 0 {
		fmt.Println("- No records found")
		return
	}
	var list []string
	for r := range records {
		list = append(list, r)
	}
	sort.Strings(list)
	for _, r := range list {
		if formatter != nil {
			fmt.Println(formatter(r))
		} else {
			fmt.Printf("- %s\n", r)
		}
	}
}

// formatMXWithTTL prints "<record> - TTL <ttl>"; record is stored as "ttl|pref host"
func formatMXWithTTL(record string) string {
	if i := strings.Index(record, "|"); i >= 0 {
		return fmt.Sprintf("- %s - TTL %s", record[i+1:], record[:i])
	}
	return "- " + record
}

// formatTXTWithTTL prints "<record> - TTL <ttl>"; record is stored as "ttl|text"
func formatTXTWithTTL(record string) string {
	if i := strings.Index(record, "|"); i >= 0 {
		return fmt.Sprintf("- %s - TTL %s", record[i+1:], record[:i])
	}
	return "- " + record
}

func formatSOA(record string) string {
	parts := strings.Split(record, " ")
	if len(parts) >= 7 {
		return fmt.Sprintf("- Primary NS: %s\n  Email: %s\n  Serial: %s\n  Refresh: %s\n  Retry: %s\n  Expire: %s\n  Minimum TTL: %s",
			parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6])
	}
	return "- " + record
}

func formatHINFO(record string) string {
	parts := strings.SplitN(record, " ", 2)
	if len(parts) >= 2 {
		return fmt.Sprintf("- CPU: %s, OS: %s", parts[0], parts[1])
	}
	return "- " + record
}

func formatSRV(record string) string {
	parts := strings.Split(record, " ")
	if len(parts) >= 4 {
		return fmt.Sprintf("- Target: %s, Port: %s, Priority: %s, Weight: %s",
			parts[0], parts[1], parts[2], parts[3])
	}
	return "- " + record
}

func formatCAA(record string) string {
	parts := strings.SplitN(record, " ", 3)
	if len(parts) >= 3 {
		return fmt.Sprintf("- Flag: %s, Tag: %s, Value: %s", parts[0], parts[1], parts[2])
	}
	return "- " + record
}

func formatLOC(record string) string {
	parts := strings.Split(record, " ")
	if len(parts) >= 6 {
		return fmt.Sprintf("- Latitude: %s°\n  Longitude: %s°\n  Altitude: %sm\n  Size: %sm\n  Horizontal Precision: %sm\n  Vertical Precision: %sm",
			parts[0], parts[1], parts[2], parts[3], parts[4], parts[5])
	}
	return "- " + record
}

func formatDS(record string) string {
	parts := strings.SplitN(record, " ", 4)
	if len(parts) >= 4 {
		return fmt.Sprintf("- Key Tag: %s\n  Algorithm: %s\n  Digest Type: %s\n  Digest: %s",
			parts[0], parts[1], parts[2], parts[3])
	}
	return "- " + record
}

func formatDNSKEY(record string) string {
	parts := strings.SplitN(record, " ", 4)
	if len(parts) >= 4 {
		return fmt.Sprintf("- Key Tag: %s\n  Algorithm: %s\n  Flags: %s\n  Public Key: %s",
			parts[0], parts[1], parts[2], parts[3])
	}
	return "- " + record
}
