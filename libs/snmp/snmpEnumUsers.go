package snmp

import (
	"fmt"
	"log"
	"net"
	"strings"
)

type SNMPUserEnumerator struct {
	Target    string
	Port      uint16
	Community string
}

func NewSNMPUserEnumerator(target string, port uint16, community string) *SNMPUserEnumerator {
	return &SNMPUserEnumerator{
		Target:    target,
		Port:      port,
		Community: community,
	}
}

func (e *SNMPUserEnumerator) Run() {
	err := e.enumerateUsers()
	if err != nil {
		log.Printf("Error enumerating users: %v", err)
	}
}

func (e *SNMPUserEnumerator) enumerateUsers() error {
	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", e.Target, e.Port))
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	sysDescrOID := "1.3.6.1.2.1.1.1.0"
	sysDescr, err := e.snmpGet(conn, sysDescrOID)
	if err != nil {
		return fmt.Errorf("failed to get sysDescr: %v", err)
	}

	sysDescValue := string(sysDescr)
	sysDescValue = strings.ReplaceAll(sysDescValue, "\r\n", " ")

	sysDescMap := map[string]string{
		"1.3.6.1.4.1.77.1.2.25": "Windows",
		"1.3.6.1.4.1.42.3.12.1.8": "Sun",
	}

	var matchingOIDs []string
	for oid, platform := range sysDescMap {
		if strings.Contains(sysDescValue, platform) {
			matchingOIDs = append(matchingOIDs, oid)
		}
	}

	if len(matchingOIDs) == 0 {
		log.Printf("Skipping unsupported sysDescr: '%s'", sysDescValue)
		return nil
	}

	var users []string
	for _, oid := range matchingOIDs {
		userList, err := e.snmpWalk(conn, oid)
		if err != nil {
			log.Printf("Error walking OID %s: %v", oid, err)
			continue
		}
		users = append(users, userList...)
	}

	if len(users) > 0 {
		users = unique(users)
		log.Printf("Found %d users: %s", len(users), strings.Join(users, ", "))
	}

	return nil
}

func (e *SNMPUserEnumerator) snmpGet(conn net.Conn, oid string) (string, error) {
	// Construct SNMP GET request
	request := []byte{
		0x30, 0x1C, // SNMP PDU
		0x02, 0x01, 0x00, // Version
		0x04, byte(len(e.Community)), // Community
	}
	request = append(request, []byte(e.Community)...)
	request = append(request, 0xA0, 0x0E) // GetRequest PDU
	request = append(request, 0x02, 0x01, 0x00) // Request ID
	request = append(request, 0x02, 0x01, 0x00) // Error Status
	request = append(request, 0x02, 0x01, 0x00) // Error Index
	request = append(request, 0x30, 0x0A) // Variable Bindings
	request = append(request, 0x30, 0x08) // Sequence
	request = append(request, 0x06, byte(len(oid))) // OID
	request = append(request, []byte(oid)...)
	request = append(request, 0x05, 0x00) // Null

	// Send the SNMP GET request
	_, err := conn.Write(request)
	if err != nil {
		return "", fmt.Errorf("failed to send SNMP GET request: %v", err)
	}

	// Read the response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return "", fmt.Errorf("failed to read SNMP response: %v", err)
	}

	// Parse the response (this is a simplified example)
	if n < 0 {
		return "", fmt.Errorf("invalid response length")
	}

	// Extract the value from the response
	// This is a placeholder; you need to decode the actual value properly
	// For simplicity, we assume the value is at a fixed position
	value := string(response[0:n]) // Adjust this based on actual response parsing

	return value, nil
}

func (e *SNMPUserEnumerator) snmpWalk(conn net.Conn, oid string) ([]string, error) {
	// Construct SNMP WALK request (similar to GET but with a different PDU type)
	request := []byte{
		0x30, 0x1C, // SNMP PDU
		0x02, 0x01, 0x00, // Version
		0x04, byte(len(e.Community)), // Community
	}
	request = append(request, []byte(e.Community)...)
	request = append(request, 0xA1, 0x0E) // GetNextRequest PDU
	request = append(request, 0x02, 0x01, 0x00) // Request ID
	request = append(request, 0x02, 0x01, 0x00) // Error Status
	request = append(request, 0x02, 0x01, 0x00) // Error Index
	request = append(request, 0x30, 0x0A) // Variable Bindings
	request = append(request, 0x30, 0x08) // Sequence
	request = append(request, 0x06, byte(len(oid))) // OID
	request = append(request, []byte(oid)...)
	request = append(request, 0x05, 0x00) // Null

	// Send the SNMP WALK request
	_, err := conn.Write(request)
	if err != nil {
		return nil, fmt.Errorf("failed to send SNMP WALK request: %v", err)
	}

	// Read the response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read SNMP response: %v", err)
	}

	// Parse the response (this is a simplified example)
	if n < 0 {
		return nil, fmt.Errorf("invalid response length")
	}

	// Extract user values from the response
	// This is a placeholder; you need to decode the actual response properly
	users := []string{"user1", "user2"} // Replace with actual parsing logic

	return users, nil
}

func unique(strings []string) []string {
	uniqueMap := make(map[string]struct{})
	for _, str := range strings {
		uniqueMap[str] = struct{}{}
	}

	var uniqueStrings []string
	for str := range uniqueMap {
		uniqueStrings = append(uniqueStrings, str)
	}
	return uniqueStrings
}

// SNMPEnumUsers is a function that takes an IP address and enumerates users.
func SNMPEnumUsers(ipAddress string) {
	enumerator := NewSNMPUserEnumerator(ipAddress, 161, "public") // Default SNMP port is 161
	enumerator.Run()
}
