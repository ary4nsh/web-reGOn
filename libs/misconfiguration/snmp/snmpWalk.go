package snmp

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// SNMP protocol constants
const (
	
	snmpVersion2c = 0x01

	// PDU types
	getNextRequest  = 0xa1

	// Variable binding types
	nullType         = 0x05
	integerType      = 0x02
	octetStringType  = 0x04
	objectIDType     = 0x06
	ipAddressType    = 0x40
	counterType      = 0x41
	gaugeType        = 0x42
	timeTicksType    = 0x43
	noSuchObjectType = 0x80
	noSuchInstType   = 0x81
	endOfMibViewType = 0x82
)

// SNMPPdu represents an SNMP Protocol Data Unit
type SNMPPdu struct {
	Name  string
	Type  byte
	Value interface{}
}

// SNMPPacket represents an SNMP packet
type SNMPPacket struct {
	Version       byte
	Community     string
	RequestType   byte
	RequestID     int
	ErrorStatus   int
	ErrorIndex    int
	VariableBindings []SNMPPdu
}

// parseBigInt parses an ASN.1 INTEGER into an int64
func parseBigInt(data []byte) int64 {
	result := int64(0)
	isNegative := false

	if len(data) > 0 && (data[0]&0x80) == 0x80 {
		isNegative = true
		// Two's complement
		for i := 0; i < len(data); i++ {
			data[i] = ^data[i]
		}
		// Add 1
		for i := len(data) - 1; i >= 0; i-- {
			data[i]++
			if data[i] != 0 {
				break
			}
		}
	}

	for i := 0; i < len(data); i++ {
		result = (result << 8) | int64(data[i])
	}

	if isNegative {
		result = -result
	}

	return result
}

// parseUint parses an ASN.1 unsigned integer into a uint64
func parseUint(data []byte) uint64 {
	result := uint64(0)
	for i := 0; i < len(data); i++ {
		result = (result << 8) | uint64(data[i])
	}
	return result
}

// parseOID parses an ASN.1 OBJECT IDENTIFIER into a string
func parseOID(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// First byte is 40*x + y
	result := []string{fmt.Sprintf("%d", data[0]/40), fmt.Sprintf("%d", data[0]%40)}

	var val uint64
	for i := 1; i < len(data); i++ {
		val = (val << 7) | uint64(data[i]&0x7f)
		if data[i]&0x80 == 0 {
			result = append(result, fmt.Sprintf("%d", val))
			val = 0
		}
	}

	return "." + strings.Join(result, ".")
}

// encodeOID encodes a string OID into ASN.1 format
func encodeOID(oid string) ([]byte, error) {
	if !strings.HasPrefix(oid, ".") {
		return nil, fmt.Errorf("invalid OID format: %s", oid)
	}

	parts := strings.Split(strings.TrimPrefix(oid, "."), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid OID format: %s", oid)
	}

	// First two parts are encoded as 40*X + Y
	x, err := parseInt(parts[0])
	if err != nil {
		return nil, err
	}

	y, err := parseInt(parts[1])
	if err != nil {
		return nil, err
	}

	result := []byte{byte(40*x + y)}

	// Encode the rest
	for i := 2; i < len(parts); i++ {
		val, err := parseInt(parts[i])
		if err != nil {
			return nil, err
		}

		// Encode val using 7 bits per byte
		if val < 128 {
			result = append(result, byte(val))
		} else {
			bytes := []byte{}
			for val > 0 {
				bytes = append([]byte{byte(val & 0x7f)}, bytes...)
				val >>= 7
			}
			// Set high bit on all bytes except the last one
			for i := 0; i < len(bytes)-1; i++ {
				bytes[i] |= 0x80
			}
			result = append(result, bytes...)
		}
	}

	return result, nil
}

// parseInt tries to parse a string to an integer
func parseInt(s string) (int, error) {
	var val int
	_, err := fmt.Sscanf(s, "%d", &val)
	return val, err
}

// encodeTLV encodes a Type-Length-Value
func encodeTLV(t byte, v []byte) []byte {
	l := len(v)
	result := []byte{t}

	if l < 128 {
		result = append(result, byte(l))
	} else if l < 256 {
		result = append(result, 0x81, byte(l))
	} else {
		result = append(result, 0x82, byte(l>>8), byte(l&0xff))
	}

	return append(result, v...)
}

// encodeInteger encodes an integer
func encodeInteger(i int) []byte {
	// Find minimum number of bytes needed
	var n int
	if i == 0 {
		n = 1
	} else {
		n = 0
		x := i
		if i < 0 {
			x = -x - 1
		}
		for x > 0 {
			x >>= 8
			n++
		}
	}

	// Encode the integer
	result := make([]byte, n)
	x := i
	for j := n - 1; j >= 0; j-- {
		result[j] = byte(x & 0xff)
		x >>= 8
	}

	return encodeTLV(integerType, result)
}

// encodeOctetString encodes a string
func encodeOctetString(s string) []byte {
	return encodeTLV(octetStringType, []byte(s))
}

// encodeNull encodes a null value
func encodeNull() []byte {
	return encodeTLV(nullType, []byte{})
}

// encodeVarBind encodes a variable binding
func encodeVarBind(oid string) ([]byte, error) {
	oidBytes, err := encodeOID(oid)
	if err != nil {
		return nil, err
	}

	oidEncoded := encodeTLV(objectIDType, oidBytes)
	nullEncoded := encodeNull()

	// Sequence of OID and NULL
	result := encodeTLV(0x30, append(oidEncoded, nullEncoded...))
	return result, nil
}

// createGetNextRequest creates an SNMP GetNext PDU
func createGetNextRequest(community string, oid string, requestID int) ([]byte, error) {
	// Encode the variable binding
	varBind, err := encodeVarBind(oid)
	if err != nil {
		return nil, err
	}

	// Encode the variable bindings as a sequence
	varBinds := encodeTLV(0x30, varBind)

	// Create PDU with all components
	reqIDBytes := encodeInteger(requestID)
	errorStatusBytes := encodeInteger(0)
	errorIndexBytes := encodeInteger(0)
	
	pdu := make([]byte, 0)
	pdu = append(pdu, reqIDBytes...)
	pdu = append(pdu, errorStatusBytes...)
	pdu = append(pdu, errorIndexBytes...)
	pdu = append(pdu, varBinds...)

	// Encode PDU
	pduEncoded := encodeTLV(getNextRequest, pdu)

	// Encode SNMP packet components
	versionEncoded := encodeInteger(int(snmpVersion2c))
	communityEncoded := encodeOctetString(community)

	// Encode SNMP message
	message := make([]byte, 0)
	message = append(message, versionEncoded...)
	message = append(message, communityEncoded...)
	message = append(message, pduEncoded...)

	// Encode as sequence
	result := encodeTLV(0x30, message)
	return result, nil
}

// parseVarBinds parses the variable bindings from an SNMP response
func parseVarBinds(data []byte) ([]SNMPPdu, error) {
	var pdus []SNMPPdu
	
	// Assuming data is the variable bindings sequence
	rest := data
	for len(rest) > 0 {
		// Each var bind is a sequence
		if rest[0] != 0x30 {
			return nil, fmt.Errorf("expected sequence tag 0x30, got 0x%02x", rest[0])
		}
		
		// Parse the length
		seqLen := 0
		idx := 1
		
		if rest[idx] < 0x80 {
			seqLen = int(rest[idx])
			idx++
		} else if rest[idx] == 0x81 {
			seqLen = int(rest[idx+1])
			idx += 2
		} else if rest[idx] == 0x82 {
			seqLen = int(rest[idx+1])<<8 | int(rest[idx+2])
			idx += 3
		} else {
			return nil, fmt.Errorf("unsupported length encoding: 0x%02x", rest[idx])
		}
		
		if idx+seqLen > len(rest) {
			return nil, fmt.Errorf("variable binding sequence extends beyond data")
		}
		
		varBind := rest[idx:idx+seqLen]
		rest = rest[idx+seqLen:]
		
		// Each var bind has an OID and a value
		if len(varBind) < 2 || varBind[0] != objectIDType {
			return nil, fmt.Errorf("expected object identifier")
		}
		
		// Parse OID
		oidIdx := 1
		oidLen := 0
		
		if varBind[oidIdx] < 0x80 {
			oidLen = int(varBind[oidIdx])
			oidIdx++
		} else if varBind[oidIdx] == 0x81 {
			oidLen = int(varBind[oidIdx+1])
			oidIdx += 2
		} else if varBind[oidIdx] == 0x82 {
			oidLen = int(varBind[oidIdx+1])<<8 | int(varBind[oidIdx+2])
			oidIdx += 3
		} else {
			return nil, fmt.Errorf("unsupported OID length encoding")
		}
		
		if oidIdx+oidLen > len(varBind) {
			return nil, fmt.Errorf("OID extends beyond var bind")
		}
		
		oidBytes := varBind[oidIdx:oidIdx+oidLen]
		oid := parseOID(oidBytes)
		
		// Parse value
		valIdx := oidIdx + oidLen
		if valIdx >= len(varBind) {
			return nil, fmt.Errorf("no value in var bind")
		}
		
		valType := varBind[valIdx]
		valIdx++
		
		valLen := 0
		if valIdx < len(varBind) {
			if varBind[valIdx] < 0x80 {
				valLen = int(varBind[valIdx])
				valIdx++
			} else if varBind[valIdx] == 0x81 {
				valLen = int(varBind[valIdx+1])
				valIdx += 2
			} else if varBind[valIdx] == 0x82 {
				valLen = int(varBind[valIdx+1])<<8 | int(varBind[valIdx+2])
				valIdx += 3
			} else {
				return nil, fmt.Errorf("unsupported value length encoding")
			}
		}
		
		if valIdx+valLen > len(varBind) {
			return nil, fmt.Errorf("value extends beyond var bind")
		}
		
		valBytes := varBind[valIdx:valIdx+valLen]
		
		// Create PDU based on value type
		pdu := SNMPPdu{
			Name: oid,
			Type: valType,
		}
		
		switch valType {
		case integerType:
			pdu.Value = parseBigInt(valBytes)
		case octetStringType:
			pdu.Value = string(valBytes)
		case objectIDType:
			pdu.Value = parseOID(valBytes)
		case ipAddressType:
			if len(valBytes) == 4 {
				pdu.Value = net.IP(valBytes)
			} else {
				pdu.Value = valBytes
			}
		case counterType, gaugeType:
			pdu.Value = parseUint(valBytes)
		case timeTicksType:
			pdu.Value = parseUint(valBytes)
		default:
			pdu.Value = valBytes
		}
		
		pdus = append(pdus, pdu)
	}
	
	return pdus, nil
}

// parseResponse parses an SNMP response packet
func parseResponse(data []byte) (*SNMPPacket, error) {
	if len(data) < 2 || data[0] != 0x30 {
		return nil, fmt.Errorf("invalid SNMP packet: not a sequence")
	}
	
	// Parse the packet
	idx := 1
	if data[idx] < 0x80 {
		idx++
	} else if data[idx] == 0x81 {
		idx += 2
	} else if data[idx] == 0x82 {
		idx += 3
	} else {
		return nil, fmt.Errorf("unsupported length encoding")
	}
	
	// Version
	if data[idx] != integerType {
		return nil, fmt.Errorf("expected integer for version")
	}
	
	verIdx := idx + 1
	if data[verIdx] != 1 {
		return nil, fmt.Errorf("expected 1-byte version")
	}
	verIdx++
	
	packet := &SNMPPacket{
		Version: data[verIdx],
	}
	verIdx++
	
	// Community string
	if data[verIdx] != octetStringType {
		return nil, fmt.Errorf("expected octet string for community")
	}
	
	commIdx := verIdx + 1
	commLen := int(data[commIdx])
	commIdx++
	
	packet.Community = string(data[commIdx:commIdx+commLen])
	commIdx += commLen
	
	// PDU
	packet.RequestType = data[commIdx]
	pduIdx := commIdx + 1
	
	pduLen := 0
	if data[pduIdx] < 0x80 {
		pduLen = int(data[pduIdx])
		pduIdx++
	} else if data[pduIdx] == 0x81 {
		pduLen = int(data[pduIdx+1])
		pduIdx += 2
	} else if data[pduIdx] == 0x82 {
		pduLen = int(data[pduIdx+1])<<8 | int(data[pduIdx+2])
		pduIdx += 3
	} else {
		return nil, fmt.Errorf("unsupported PDU length encoding")
	}
	
	pduEnd := pduIdx + pduLen
	_ = pduEnd  // Ensure pduEnd is used (helps with bounds checking)
	
	// Request ID
	if data[pduIdx] != integerType {
		return nil, fmt.Errorf("expected integer for request ID")
	}
	
	reqIDIdx := pduIdx + 1
	reqIDLen := int(data[reqIDIdx])
	reqIDIdx++
	
	packet.RequestID = int(parseBigInt(data[reqIDIdx:reqIDIdx+reqIDLen]))
	reqIDIdx += reqIDLen
	
	// Error status
	if data[reqIDIdx] != integerType {
		return nil, fmt.Errorf("expected integer for error status")
	}
	
	errStatIdx := reqIDIdx + 1
	errStatLen := int(data[errStatIdx])
	errStatIdx++
	
	packet.ErrorStatus = int(parseBigInt(data[errStatIdx:errStatIdx+errStatLen]))
	errStatIdx += errStatLen
	
	// Error index
	if data[errStatIdx] != integerType {
		return nil, fmt.Errorf("expected integer for error index")
	}
	
	errIdxIdx := errStatIdx + 1
	errIdxLen := int(data[errIdxIdx])
	errIdxIdx++
	
	packet.ErrorIndex = int(parseBigInt(data[errIdxIdx:errIdxIdx+errIdxLen]))
	errIdxIdx += errIdxLen
	
	// Variable bindings
	if data[errIdxIdx] != 0x30 {
		return nil, fmt.Errorf("expected sequence for variable bindings")
	}
	
	varBindIdx := errIdxIdx + 1
	varBindLen := 0
	
	if data[varBindIdx] < 0x80 {
		varBindLen = int(data[varBindIdx])
		varBindIdx++
	} else if data[varBindIdx] == 0x81 {
		varBindLen = int(data[varBindIdx+1])
		varBindIdx += 2
	} else if data[varBindIdx] == 0x82 {
		varBindLen = int(data[varBindIdx+1])<<8 | int(data[varBindIdx+2])
		varBindIdx += 3
	} else {
		return nil, fmt.Errorf("unsupported var bind length encoding")
	}
	
	if varBindIdx+varBindLen > len(data) {
		return nil, fmt.Errorf("variable bindings extend beyond packet")
	}
	
	varBinds, err := parseVarBinds(data[varBindIdx:varBindIdx+varBindLen])
	if err != nil {
		return nil, err
	}
	
	packet.VariableBindings = varBinds
	return packet, nil
}

// FormatTimeTicks formats time ticks into a human-readable format
func FormatTimeTicks(timeticks uint64) string {
	days := timeticks / 8640000
	hours := (timeticks % 8640000) / 360000
	minutes := (timeticks % 360000) / 6000
	seconds := (timeticks % 6000) / 100
	centiseconds := timeticks % 100
	return fmt.Sprintf("%d days, %02d:%02d:%02d.%02d", days, hours, minutes, seconds, centiseconds)
}

// SNMPWalk performs an SNMP walk on the specified IP address
func SNMPWalk(ipAddress string) {
	port := 161         // SNMP default port
	community := "public"  // SNMP community string
	timeout := 5 * time.Second
	
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", ipAddress, port), timeout)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	
	// Set read/write deadlines
	err = conn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		log.Fatalf("Failed to set deadline: %v", err)
	}
	
	// Start with the standard MIB-2 OID
	currentOID := ".1.3.6.1.2.1"
	requestID := 1
	endOfMib := false
	
	for !endOfMib {
		// Create and send GetNext request
		request, err := createGetNextRequest(community, currentOID, requestID)
		if err != nil {
			log.Fatalf("Failed to create request: %v", err)
		}
		
		_, err = conn.Write(request)
		if err != nil {
			log.Fatalf("Failed to send request: %v", err)
		}
		
		// Receive response
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			log.Fatalf("Failed to receive response: %v", err)
		}
		
		// Parse response
		packet, err := parseResponse(buf[:n])
		if err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}
		
		// Check if response has variable bindings
		if len(packet.VariableBindings) == 0 {
			log.Printf("No variable bindings in response")
			break
		}
		
		// Process variable bindings
		for _, pdu := range packet.VariableBindings {
			// Check if we've reached the end of the MIB
			if pdu.Type == endOfMibViewType || pdu.Type == noSuchObjectType || pdu.Type == noSuchInstType {
				endOfMib = true
				break
			}
			
			// Check if we've moved beyond our root OID
			if !strings.HasPrefix(pdu.Name, ".1.3.6.1.2.1") {
				endOfMib = true
				break
			}
			
			// Format the output
			var value string
			switch pdu.Type {
			case octetStringType:
				if s, ok := pdu.Value.(string); ok {
					// Check if string is printable ASCII
					printable := true
					for _, c := range s {
						if c < 32 || c > 126 {
							printable = false
							break
						}
					}
					
					if printable {
						value = fmt.Sprintf("STRING: %s", s)
					} else {
						// Format as hex
						var hexStr string
						for _, b := range s {
							hexStr += fmt.Sprintf("%02x ", b)
						}
						value = fmt.Sprintf("Hex-STRING: %s", strings.TrimSpace(hexStr))
					}
				} else {
					value = fmt.Sprintf("STRING: %v", pdu.Value)
				}
			case objectIDType:
				value = fmt.Sprintf("OID: %s", pdu.Value)
			case integerType:
				if i, ok := pdu.Value.(int64); ok {
					value = fmt.Sprintf("INTEGER: %d", i)
				} else {
					value = fmt.Sprintf("INTEGER: %v", pdu.Value)
				}
			case ipAddressType:
				if ip, ok := pdu.Value.(net.IP); ok {
					value = fmt.Sprintf("IpAddress: %s", ip.String())
				} else {
					value = fmt.Sprintf("IpAddress: %v", pdu.Value)
				}
			case counterType:
				if c, ok := pdu.Value.(uint64); ok {
					value = fmt.Sprintf("Counter32: %d", c)
				} else {
					value = fmt.Sprintf("Counter32: %v", pdu.Value)
				}
			case gaugeType:
				if g, ok := pdu.Value.(uint64); ok {
					value = fmt.Sprintf("Gauge32: %d", g)
				} else {
					value = fmt.Sprintf("Gauge32: %v", pdu.Value)
				}
			case timeTicksType:
				if t, ok := pdu.Value.(uint64); ok {
					value = fmt.Sprintf("Timeticks: (%d) %s", t, FormatTimeTicks(t))
				} else {
					value = fmt.Sprintf("Timeticks: %v", pdu.Value)
				}
			default:
				value = fmt.Sprintf("Type=%d Value=%v", pdu.Type, pdu.Value)
			}
			
			fmt.Printf("%s = %s\n", pdu.Name, value)
			
			// Update current OID for next request
			currentOID = pdu.Name
		}
		
		// Increment request ID for next request
		requestID++
	}
}
