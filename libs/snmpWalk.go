package libs

import (
	"fmt"
	"log"

	"github.com/gosnmp/gosnmp"
)

// SNMPWalk performs an SNMP walk on the specified IP address.
func SNMPWalk(ipAddress string) {
	port := uint16(161)    // SNMP default port
	community := "public"  // SNMP community string

	// Create an SNMP client
	gosnmp.Default.Target = ipAddress
	gosnmp.Default.Port = port
	gosnmp.Default.Community = community
	gosnmp.Default.Version = gosnmp.Version2c

	// Connect to the SNMP device
	err := gosnmp.Default.Connect()
	if err != nil {
		log.Fatalf("Connect() err: %v", err)
	}
	defer gosnmp.Default.Conn.Close()

	// OID to start walking from
	startOID := ".1.3.6.1.2.1" // SNMPv2 MIB OID

	// Perform the SNMP walk
	err = gosnmp.Default.Walk(startOID, func(pdu gosnmp.SnmpPDU) error {
		// Format the output to match the desired format
		var value string
		switch pdu.Type {
		case gosnmp.OctetString:
			value = fmt.Sprintf("STRING: %s", pdu.Value)
		case gosnmp.ObjectIdentifier:
			value = fmt.Sprintf("OID: %s", pdu.Value)
		case gosnmp.TimeTicks:
			value = fmt.Sprintf("Timeticks: (%d) %s", pdu.Value, formatTimeTicks(pdu.Value.(uint32)))
		case gosnmp.Integer:
			value = fmt.Sprintf("INTEGER: %d", pdu.Value)
		default:
			value = fmt.Sprintf("UNKNOWN TYPE: %v", pdu.Value)
		}
		fmt.Printf("%s = %s\n", pdu.Name, value)
		return nil
	})

	if err != nil {
		log.Fatalf("Walk() err: %v", err)
	}
}

// Helper function to format Timeticks
func formatTimeTicks(timeticks uint32) string {
	days := timeticks / 8640000
	hours := (timeticks % 8640000) / 360000
	minutes := (timeticks % 360000) / 60000
	seconds := (timeticks % 60000) / 1000
	milliseconds := timeticks % 1000

	return fmt.Sprintf("%d days, %02d:%02d:%02d.%03d", days, hours, minutes, seconds, milliseconds)
}
