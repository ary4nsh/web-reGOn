package snmp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"
)

const (
	snmpVersion = 0x01 // SNMP version 2c
	community   = "public"
)

func SNMPEnumShares(ipAddress string) {
	// Create a UDP connection
	conn, err := net.Dial("udp", fmt.Sprintf("%s:161", ipAddress))
	if err != nil {
		log.Fatalf("Error connecting to SNMP agent: %v", err)
	}
	defer conn.Close()

	// Set a timeout for the connection
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Prepare SNMP GET request
	request := createSNMPGetRequest(community, []string{
		"1.3.6.1.2.1.1.1.0", // sysDescr
		"1.3.6.1.4.1.77.1.2.27.1.1", // Share Name
		"1.3.6.1.4.1.77.1.2.27.1.2", // Share Type
		"1.3.6.1.4.1.77.1.2.27.1.3", // Share Path
	})

	// Send the request
	_, err = conn.Write(request)
	if err != nil {
		log.Fatalf("Error sending SNMP request: %v", err)
	}

	// Read the response
	response := make([]byte, 2048)
	n, err := conn.Read(response)
	if err != nil {
		log.Fatalf("Error reading SNMP response: %v", err)
	}

	// Parse the response
	parseSNMPResponse(response[:n])
}

func createSNMPGetRequest(community string, oids []string) []byte {
	// SNMP PDU structure
	pdu := []byte{
		0x30, 0x00, // Sequence
		0x02, 0x01, snmpVersion, // Version
		0x04, byte(len(community)), // Community
	}
	pdu = append(pdu, []byte(community)...)

	// Create the request PDU
	pdu = append(pdu, 0xa0, 0x00) // GetRequest PDU
	pdu = append(pdu, 0x02, 0x01, 0x00) // Request ID
	pdu = append(pdu, 0x02, 0x01, 0x00) // Error Status
	pdu = append(pdu, 0x02, 0x01, 0x00) // Error Index
	pdu = append(pdu, 0x30, 0x00) // Variable Bindings

	// Add OIDs to the PDU
	for _, oid := range oids {
		oidBytes, _ := hex.DecodeString(oid)
		pdu = append(pdu, 0x30, 0x00) // Sequence for each OID
		pdu = append(pdu, 0x06, byte(len(oidBytes))) // OID
		pdu = append(pdu, oidBytes...)
		pdu = append(pdu, 0x05, 0x00) // Null
	}

	// Set the length of the PDU
	binary.BigEndian.PutUint16(pdu[1:3], uint16(len(pdu)-2))

	return pdu
}

func parseSNMPResponse(response []byte) {
	// This function should parse the SNMP response and extract the shares
	// For simplicity, we will just print the raw response
	fmt.Printf("SNMP Response: %x\n", response)
}
