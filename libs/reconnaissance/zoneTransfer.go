package reconnaissance

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// DNS message constants
const (
	// DNS Message Types
	TypeA     uint16 = 1   // IPv4 Address
	TypeNS    uint16 = 2   // Nameserver
	TypeCNAME uint16 = 5   // Canonical name
	TypeSOA   uint16 = 6   // Start of Authority
	TypePTR   uint16 = 12  // Pointer
	TypeMX    uint16 = 15  // Mail Exchange
	TypeTXT   uint16 = 16  // Text
	TypeAAAA  uint16 = 28  // IPv6 Address
	TypeSRV   uint16 = 33  // Service
	TypeAXFR  uint16 = 252 // Zone Transfer

	// DNS Classes
	ClassIN uint16 = 1 // Internet

	// DNS Header Flags
	FlagQR uint16 = 1 << 15 // Query/Response flag
	FlagRD uint16 = 1 << 8  // Recursion Desired
	FlagTC uint16 = 1 << 9  // Truncated
	FlagAA uint16 = 1 << 10 // Authoritative Answer
)

// List of DNS resolvers to try
var dnsResolvers = []string{
	"1.1.1.1:53",        // Cloudflare Primary
	"1.0.0.1:53",        // Cloudflare Secondary
	"8.8.8.8:53",        // Google Primary
	"8.8.4.4:53",        // Google Secondary
	"9.9.9.9:53",        // Quad9
	"149.112.112.112:53", // Quad9 Secondary
}

// DNSHeader represents a DNS packet header
type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QdCount uint16
	AnCount uint16
	NsCount uint16
	ArCount uint16
}

// DNSQuestion represents a DNS query question
type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

// DNSRecord represents a DNS resource record (simplified)
type DNSRecord struct {
	Name       string
	Type       uint16
	Class      uint16
	TTL        uint32
	Data       string
	RecordType string
}

func ZoneTransfer(URL string) {
	URL = strings.TrimSpace(URL)

	if URL == "" {
		fmt.Println("Domain cannot be empty")
		return
	}

	// Get NS records
	fmt.Println("Querying DNS servers for NS records...")
	nsRecords, err := getNSRecords(URL)
	if err != nil {
		fmt.Printf("Error getting NS records: %v\n", err)
		return
	}

	if len(nsRecords) == 0 {
		fmt.Println("No NS records found for domain")
		return
	}

	fmt.Printf("Found %d nameservers for %s\n", len(nsRecords), URL)
	for i, ns := range nsRecords {
		fmt.Printf("[%d] %s\n", i+1, ns)
	}

	// Try zone transfer with each NS
	atLeastOneSuccess := false
	for i, ns := range nsRecords {
		fmt.Printf("\n[%d/%d] Attempting zone transfer with NS: %s\n", 
			i+1, len(nsRecords), ns)
		
		records, err := attemptZoneTransfer(URL, ns)
		if err != nil {
			fmt.Printf("Failed: %v\n", err)
			continue
		}

		fmt.Printf("SUCCESS! Zone transfer complete with %d records\n", len(records))
		for i, record := range records {
			fmt.Printf("[%d] %s\n", i+1, record)
		}
		atLeastOneSuccess = true
		break // Successfully transferred zone, no need to try other nameservers
	}

	if !atLeastOneSuccess {
		fmt.Println("\nAll zone transfer attempts failed. The domain may have zone transfers disabled.")
	}
}

// getNSRecords gets the nameserver records for a domain
func getNSRecords(URL string) ([]string, error) {
	var lastErr error
	
	// Try each resolver until one succeeds
	for _, resolver := range dnsResolvers {
		fmt.Printf("Trying resolver %s... ", resolver)
		
		// Create a DNS message to query NS records
		msg := createDNSMessage(URL, TypeNS)
		
		// Send the query to the current DNS resolver
		conn, err := net.DialTimeout("udp", resolver, 5*time.Second)
		if err != nil {
			fmt.Println("Failed to connect")
			lastErr = fmt.Errorf("dial to %s failed: %v", resolver, err)
			continue
		}
		
		// Set timeout
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		
		// Send the query
		_, err = conn.Write(msg)
		if err != nil {
			conn.Close()
			fmt.Println("Failed to send query")
			lastErr = fmt.Errorf("write to %s failed: %v", resolver, err)
			continue
		}
		
		// Read the response
		resp := make([]byte, 1024)
		n, err := conn.Read(resp)
		conn.Close()
		
		if err != nil {
			fmt.Println("Failed to receive response")
			lastErr = fmt.Errorf("read from %s failed: %v", resolver, err)
			continue
		}
		
		// Parse the NS records
		nsRecords, err := parseNSRecords(resp[:n], URL)
		if err != nil {
			fmt.Println("Failed to parse response")
			lastErr = fmt.Errorf("parse NS records from %s failed: %v", resolver, err)
			continue
		}
		
		// If we got NS records, return them
		if len(nsRecords) > 0 {
			fmt.Printf("Success! Found %d NS records\n", len(nsRecords))
			return nsRecords, nil
		}
		
		fmt.Println("No NS records found")
	}
	
	// If we get here, all resolvers failed
	return nil, fmt.Errorf("all DNS resolvers failed: %v", lastErr)
}

// createDNSMessage creates a byte slice representing a DNS query
func createDNSMessage(URL string, qtype uint16) []byte {
	// Create the DNS header
	header := DNSHeader{
		ID:      uint16(time.Now().UnixNano() % 65535), // Random ID
		Flags:   FlagRD,                                // Standard query with recursion
		QdCount: 1,                                     // One question
		AnCount: 0,
		NsCount: 0,
		ArCount: 0,
	}
	
	// Create the DNS question
	question := DNSQuestion{
		Name:  URL,
		Type:  qtype,
		Class: ClassIN,
	}
	
	// Build the message
	msg := make([]byte, 512)
	offset := 0
	
	// Write header
	binary.BigEndian.PutUint16(msg[offset:], header.ID)
	offset += 2
	binary.BigEndian.PutUint16(msg[offset:], header.Flags)
	offset += 2
	binary.BigEndian.PutUint16(msg[offset:], header.QdCount)
	offset += 2
	binary.BigEndian.PutUint16(msg[offset:], header.AnCount)
	offset += 2
	binary.BigEndian.PutUint16(msg[offset:], header.NsCount)
	offset += 2
	binary.BigEndian.PutUint16(msg[offset:], header.ArCount)
	offset += 2
	
	// Write question - domain name in DNS format
	parts := strings.Split(question.Name, ".")
	for _, part := range parts {
		if len(part) > 0 {
			msg[offset] = byte(len(part))
			offset++
			copy(msg[offset:], part)
			offset += len(part)
		}
	}
	msg[offset] = 0 // Terminating zero
	offset++
	
	// Write question type and class
	binary.BigEndian.PutUint16(msg[offset:], question.Type)
	offset += 2
	binary.BigEndian.PutUint16(msg[offset:], question.Class)
	offset += 2
	
	return msg[:offset]
}

// encodeDNSName encodes a domain name in DNS format
func encodeDNSName(URL string) []byte {
	var result []byte
	parts := strings.Split(URL, ".")
	for _, part := range parts {
		if len(part) > 0 {
			result = append(result, byte(len(part)))
			result = append(result, []byte(part)...)
		}
	}
	result = append(result, 0) // Terminating zero
	return result
}

// parseNSRecords extracts NS records from a DNS response
func parseNSRecords(resp []byte, URL string) ([]string, error) {
	if len(resp) < 12 {
		return nil, fmt.Errorf("response too short")
	}
	
	// Extract header info
	header := DNSHeader{
		ID:      binary.BigEndian.Uint16(resp[0:2]),
		Flags:   binary.BigEndian.Uint16(resp[2:4]),
		QdCount: binary.BigEndian.Uint16(resp[4:6]),
		AnCount: binary.BigEndian.Uint16(resp[6:8]),
		NsCount: binary.BigEndian.Uint16(resp[8:10]),
		ArCount: binary.BigEndian.Uint16(resp[10:12]),
	}
	
	// Check for errors
	if (header.Flags & FlagQR) == 0 {
		return nil, fmt.Errorf("not a response")
	}
	
	rcode := header.Flags & 0xF
	if rcode != 0 {
		return nil, fmt.Errorf("DNS response code error: %d", rcode)
	}
	
	// Skip question section
	offset := 12
	for i := 0; i < int(header.QdCount); i++ {
		// Skip name
		offset = skipDNSName(resp, offset)
		if offset == -1 {
			return nil, fmt.Errorf("invalid question format")
		}
		// Skip type and class
		offset += 4
		if offset > len(resp) {
			return nil, fmt.Errorf("response truncated in question section")
		}
	}
	
	// Parse answer section for NS records
	var nsRecords []string
	recordSections := int(header.AnCount + header.NsCount) // Look in both answer and authority sections
	
	for i := 0; i < recordSections; i++ {
		if offset >= len(resp) {
			break
		}
		
		// Skip name field
		offset = skipDNSName(resp, offset)
		if offset == -1 {
			return nil, fmt.Errorf("invalid record name format")
		}
		
		// Check for truncation
		if offset+10 > len(resp) {
			return nil, fmt.Errorf("response truncated in record")
		}
		
		// Get record type and check if it's NS
		recordType := binary.BigEndian.Uint16(resp[offset:offset+2])
		offset += 2 // Skip type
		offset += 2 // Skip class
		offset += 4 // Skip TTL
		
		// Get data length
		if offset+2 > len(resp) {
			return nil, fmt.Errorf("response truncated at rdlength")
		}
		rdLength := binary.BigEndian.Uint16(resp[offset:offset+2])
		offset += 2
		
		if offset+int(rdLength) > len(resp) {
			return nil, fmt.Errorf("response truncated at rdata")
		}
		
		// Check if this is an NS record
		if recordType == TypeNS {
			// Parse nameserver domain name from RDATA
			nsName, err := decodeDNSName(resp, offset)
			if err != nil {
				return nil, fmt.Errorf("invalid NS record data: %v", err)
			}
			nsRecords = append(nsRecords, nsName)
		}
		
		// Move to next record
		offset += int(rdLength)
	}
		
	return nsRecords, nil
}

// skipDNSName skips over a DNS encoded name and returns the new offset
func skipDNSName(data []byte, offset int) int {
	if offset >= len(data) {
		return -1
	}
	
	// Keep track of the original position to detect compression loops
	startOffset := offset
	
	for {
		if offset >= len(data) {
			return -1
		}
		
		length := int(data[offset])
		if length == 0 {
			// End of name
			return offset + 1
		}
		
		if (length & 0xC0) == 0xC0 {
			// Compressed name pointer
			if offset+1 >= len(data) {
				return -1
			}
			// Skip the 2-byte pointer
			return offset + 2
		}
		
		// Regular label
		offset += length + 1
		if offset > len(data) {
			return -1
		}
		
		// Safety check for infinite loops or malformed packets
		if offset - startOffset > 255 {
			return -1
		}
	}
}

// decodeDNSName decodes a DNS encoded name starting at offset
func decodeDNSName(data []byte, offset int) (string, error) {
	var nameParts []string
	visited := make(map[int]bool) // Track visited offsets to detect compression loops
	
	for {
		if offset >= len(data) {
			return "", fmt.Errorf("unexpected end of data")
		}
		
		length := int(data[offset])
		if length == 0 {
			// End of name
			break
		}
		
		if (length & 0xC0) == 0xC0 {
			// Compressed name pointer
			if offset+1 >= len(data) {
				return "", fmt.Errorf("invalid compression pointer")
			}
			
			// Extract pointer value (14 bits)
			pointer := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			
			// Detect loops in compression pointers
			if visited[pointer] {
				return "", fmt.Errorf("compression pointer loop detected")
			}
			visited[pointer] = true
			
			// Follow the pointer
			offset = pointer
			continue
		}
		
		// Regular label
		offset++
		if offset+length > len(data) {
			return "", fmt.Errorf("label extends beyond message")
		}
		
		nameParts = append(nameParts, string(data[offset:offset+length]))
		offset += length
		
		// Safety check for malformed packets or loops
		if len(visited) > 255 || len(nameParts) > 255 {
			return "", fmt.Errorf("too many labels in name")
		}
	}
	
	return strings.Join(nameParts, "."), nil
}

// attemptZoneTransfer attempts to perform a zone transfer with the specified nameserver
func attemptZoneTransfer(URL, nameserver string) ([]string, error) {
	// Create a dialer with timeout
	dialer := net.Dialer{Timeout: 10 * time.Second}
	
	// Use TCP for zone transfers
	conn, err := dialer.Dial("tcp", nameserver+":53")
	if err != nil {
		return nil, fmt.Errorf("TCP connection failed: %v", err)
	}
	defer conn.Close()
	
	// Set timeout for the entire operation
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	
	// Create AXFR query
	query := createAXFRMessage(URL)
	
	// Send message length first (TCP DNS requires 2-byte length prefix)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(query)))
	_, err = conn.Write(length)
	if err != nil {
		return nil, fmt.Errorf("write length failed: %v", err)
	}
	
	// Send the actual message
	_, err = conn.Write(query)
	if err != nil {
		return nil, fmt.Errorf("write message failed: %v", err)
	}
	
	// Read and parse the response(s)
	var records []string
	soaCount := 0 // Count SOA records to detect end of transfer
	
	for {
		// Read the 2-byte length prefix
		lengthBuf := make([]byte, 2)
		_, err = io.ReadFull(conn, lengthBuf)
		if err != nil {
			if err == io.EOF {
				break // End of transfer
			}
			return nil, fmt.Errorf("read length failed: %v", err)
		}
		
		msgLen := binary.BigEndian.Uint16(lengthBuf)
		if msgLen == 0 {
			break
		}
		
		// Read the message of specified length
		respBuf := make([]byte, msgLen)
		_, err = io.ReadFull(conn, respBuf)
		if err != nil {
			return nil, fmt.Errorf("read message failed: %v", err)
		}
		
		// Parse the response and extract records
		zoneRecords, foundSOA, err := parseZoneTransferResponse(respBuf)
		if err != nil {
			return nil, fmt.Errorf("parse response failed: %v", err)
		}
		
		records = append(records, zoneRecords...)
		soaCount += foundSOA
		
		// A zone transfer typically starts and ends with SOA records
		// When we've seen 2 SOA records, we're done
		if soaCount >= 2 {
			break
		}
	}
	
	if len(records) == 0 {
		return nil, fmt.Errorf("no records received or zone transfer denied")
	}
	
	return records, nil
}

// createAXFRMessage creates a message for a zone transfer query
func createAXFRMessage(URL string) []byte {
	// Create the DNS header for AXFR query
	header := DNSHeader{
		ID:      uint16(time.Now().UnixNano() % 65535), // Random ID
		Flags:   0,                                     // Standard query
		QdCount: 1,                                     // One question
		AnCount: 0,
		NsCount: 0,
		ArCount: 0,
	}
	
	// Build the message
	msg := make([]byte, 512)
	offset := 0
	
	// Write header
	binary.BigEndian.PutUint16(msg[offset:], header.ID)
	offset += 2
	binary.BigEndian.PutUint16(msg[offset:], header.Flags)
	offset += 2
	binary.BigEndian.PutUint16(msg[offset:], header.QdCount)
	offset += 2
	binary.BigEndian.PutUint16(msg[offset:], header.AnCount)
	offset += 2
	binary.BigEndian.PutUint16(msg[offset:], header.NsCount)
	offset += 2
	binary.BigEndian.PutUint16(msg[offset:], header.ArCount)
	offset += 2
	
	// Write domain name in DNS format
	parts := strings.Split(URL, ".")
	for _, part := range parts {
		if len(part) > 0 {
			msg[offset] = byte(len(part))
			offset++
			copy(msg[offset:], part)
			offset += len(part)
		}
	}
	msg[offset] = 0 // Terminating zero
	offset++
	
	// Write question type (AXFR) and class (IN)
	binary.BigEndian.PutUint16(msg[offset:], TypeAXFR)
	offset += 2
	binary.BigEndian.PutUint16(msg[offset:], ClassIN)
	offset += 2
	
	return msg[:offset]
}

// parseZoneTransferResponse extracts records from a zone transfer response
func parseZoneTransferResponse(resp []byte) ([]string, int, error) {
	if len(resp) < 12 {
		return nil, 0, fmt.Errorf("response too short")
	}
	
	// Extract header info
	header := DNSHeader{
		ID:      binary.BigEndian.Uint16(resp[0:2]),
		Flags:   binary.BigEndian.Uint16(resp[2:4]),
		QdCount: binary.BigEndian.Uint16(resp[4:6]),
		AnCount: binary.BigEndian.Uint16(resp[6:8]),
		NsCount: binary.BigEndian.Uint16(resp[8:10]),
		ArCount: binary.BigEndian.Uint16(resp[10:12]),
	}
	
	// Check for errors
	if (header.Flags & FlagQR) == 0 {
		return nil, 0, fmt.Errorf("not a response")
	}
	
	rcode := header.Flags & 0xF
	if rcode != 0 {
		return nil, 0, fmt.Errorf("DNS error code: %d", rcode)
	}
	
	// Skip question section
	offset := 12
	for i := 0; i < int(header.QdCount); i++ {
		offset = skipDNSName(resp, offset)
		if offset == -1 {
			return nil, 0, fmt.Errorf("invalid question format")
		}
		offset += 4 // Skip type and class
		if offset > len(resp) {
			return nil, 0, fmt.Errorf("response truncated in question section")
		}
	}
	
	// Parse answer records
	var records []string
	soaCount := 0 // Count SOA records
	
	totalRecords := int(header.AnCount + header.NsCount + header.ArCount)
	for i := 0; i < totalRecords; i++ {
		if offset >= len(resp) {
			break
		}
		
		// Read the name
		name, err := decodeDNSName(resp, offset)
		if err != nil {
			return nil, soaCount, fmt.Errorf("invalid record name: %v", err)
		}
		
		// Skip to the fixed part of the record
		offset = skipDNSName(resp, offset)
		if offset == -1 || offset+10 > len(resp) {
			return nil, soaCount, fmt.Errorf("invalid record format")
		}
		
		// Extract record type, class, TTL, and length
		recordType := binary.BigEndian.Uint16(resp[offset:offset+2])
		offset += 2
		
		// Skip class (we know it's IN)
		offset += 2
		
		ttl := binary.BigEndian.Uint32(resp[offset:offset+4])
		offset += 4
		
		rdLength := binary.BigEndian.Uint16(resp[offset:offset+2])
		offset += 2
		
		if offset+int(rdLength) > len(resp) {
			return nil, soaCount, fmt.Errorf("record data extends beyond message")
		}
		
		// Count SOA records
		if recordType == TypeSOA {
			soaCount++
		}
		
		// Format record type as string
		recordTypeStr := formatRecordType(recordType)
		
		// Format the record data based on type
		recordData := formatRecordData(resp, offset, recordType, rdLength)
		
		// Create a readable record string
		record := fmt.Sprintf("%s\t%d\tIN\t%s\t%s", name, ttl, recordTypeStr, recordData)
		records = append(records, record)
		
		// Move to next record
		offset += int(rdLength)
	}
	
	return records, soaCount, nil
}

// formatRecordType returns a string representation of a record type
func formatRecordType(recordType uint16) string {
	switch recordType {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeSRV:
		return "SRV"
	default:
		return fmt.Sprintf("TYPE%d", recordType)
	}
}

// formatRecordData formats the RDATA section based on record type
func formatRecordData(data []byte, offset int, recordType uint16, rdLength uint16) string {
	switch recordType {
	case TypeA:
		if rdLength == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", 
				data[offset], data[offset+1], data[offset+2], data[offset+3])
		}
	case TypeAAAA:
		if rdLength == 16 {
			return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
				binary.BigEndian.Uint16(data[offset:offset+2]),
				binary.BigEndian.Uint16(data[offset+2:offset+4]),
				binary.BigEndian.Uint16(data[offset+4:offset+6]),
				binary.BigEndian.Uint16(data[offset+6:offset+8]),
				binary.BigEndian.Uint16(data[offset+8:offset+10]),
				binary.BigEndian.Uint16(data[offset+10:offset+12]),
				binary.BigEndian.Uint16(data[offset+12:offset+14]),
				binary.BigEndian.Uint16(data[offset+14:offset+16]))
		}
	case TypeNS, TypeCNAME, TypePTR:
		name, err := decodeDNSName(data, offset)
		if err == nil {
			return name
		}
	case TypeMX:
		if rdLength >= 2 {
			preference := binary.BigEndian.Uint16(data[offset:offset+2])
			name, err := decodeDNSName(data, offset+2)
			if err == nil {
				return fmt.Sprintf("%d %s", preference, name)
			}
		}
	case TypeTXT:
		if rdLength > 0 {
			txtLen := int(data[offset])
			if txtLen > 0 && offset+1+txtLen <= len(data) {
				return fmt.Sprintf("\"%s\"", string(data[offset+1:offset+1+txtLen]))
			}
		}
	case TypeSOA:
		mname, err1 := decodeDNSName(data, offset)
		if err1 != nil {
			return "<error parsing SOA>"
		}
		
		// Skip to after MNAME
		pos := skipDNSName(data, offset)
		if pos == -1 {
			return "<error parsing SOA>"
		}
		
		rname, err2 := decodeDNSName(data, pos)
		if err2 != nil {
			return "<error parsing SOA>"
		}
		
		// Skip to after RNAME
		pos = skipDNSName(data, pos)
		if pos == -1 || pos+20 > len(data) {
			return "<error parsing SOA>"
		}
		
		serial := binary.BigEndian.Uint32(data[pos:pos+4])
		refresh := binary.BigEndian.Uint32(data[pos+4:pos+8])
		retry := binary.BigEndian.Uint32(data[pos+8:pos+12])
		expire := binary.BigEndian.Uint32(data[pos+12:pos+16])
		minimum := binary.BigEndian.Uint32(data[pos+16:pos+20])
		
		return fmt.Sprintf("%s %s %d %d %d %d %d", 
			mname, rname, serial, refresh, retry, expire, minimum)
	}
	
	// Default - just show length
	return fmt.Sprintf("<RDATA: %d bytes>", rdLength)
}
