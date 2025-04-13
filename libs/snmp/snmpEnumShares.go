package snmp

import (
	"fmt"
	"log"

	"github.com/gosnmp/gosnmp"
)

func SNMPEnumShares(ipAddress string) {

	// Create a new SNMP client
	snmp := &gosnmp.GoSNMP{
		Target:    ipAddress,
		Port:      161,
		Version:   gosnmp.Version2c,
		Community: "public", // Change this if needed
		Timeout:   2 * 1e9, // 2 seconds
	}

	// Connect to the SNMP agent
	err := snmp.Connect()
	if err != nil {
		log.Fatalf("Error connecting to SNMP agent: %v", err)
	}
	defer snmp.Conn.Close()

	// Check if the system is Windows
	sysDescr, err := snmp.Get([]string{"1.3.6.1.2.1.1.1.0"})
	if err != nil {
		log.Fatalf("Error getting sysDescr: %v", err)
	}

	if string(sysDescr.Variables[0].Value.([]byte)) != "" && string(sysDescr.Variables[0].Value.([]byte)) != "Windows" {
		log.Fatalf("The target is not a Windows system.")
	}

	// OID values for SMB shares
	shareTbl := []string{
		"1.3.6.1.4.1.77.1.2.27.1.1", // Share Name
		"1.3.6.1.4.1.77.1.2.27.1.2", // Share Type
		"1.3.6.1.4.1.77.1.2.27.1.3", // Share Path
	}

	var shares [][]string

	// Walk through the OIDs to get SMB shares
	for _, oid := range shareTbl {
		result, err := snmp.Get([]string{oid})
		if err != nil {
			log.Printf("Error getting OID %s: %v", oid, err)
			continue
		}
		for _, variable := range result.Variables {
			shares = append(shares, []string{oid, string(variable.Value.([]byte))})
		}
	}

	// Print the shares
	if len(shares) > 0 {
		fmt.Printf("Shares on %s:\n", ipAddress)
		for _, share := range shares {
			fmt.Printf("\t%s\n", share[1])
		}
	} else {
		fmt.Println("No shares found.")
	}
}
