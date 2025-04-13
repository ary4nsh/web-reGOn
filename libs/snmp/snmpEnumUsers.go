package snmp

import (
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"

	"github.com/gosnmp/gosnmp"
)

type SNMPUserEnumerator struct {
	Target string
	Port   uint16
}

func NewSNMPUserEnumerator(target string, port uint16) *SNMPUserEnumerator {
	return &SNMPUserEnumerator{
		Target: target,
		Port:   port,
	}
}

func (e *SNMPUserEnumerator) Run() {
	err := e.enumerateUsers()
	if err != nil {
		log.Printf("Error enumerating users: %v", err)
	}
}

func (e *SNMPUserEnumerator) enumerateUsers() error {
	// Connect to SNMP
	gosnmp.Default.Target = e.Target
	gosnmp.Default.Port = e.Port
	gosnmp.Default.Version = gosnmp.Version2c
	gosnmp.Default.Community = "public"

	err := gosnmp.Default.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer gosnmp.Default.Conn.Close()

	// Get sysDescr
	sysDescr, err := gosnmp.Default.Get([]string{"sysDescr.0"})
	if err != nil {
		return fmt.Errorf("failed to get sysDescr: %v", err)
	}

	if len(sysDescr.Variables) == 0 {
		return fmt.Errorf("no sysDescr received")
	}

	sysDescValue := string(sysDescr.Variables[0].Value.([]byte))
	sysDescValue = strings.ReplaceAll(sysDescValue, "\r\n", " ")

	// Map of OIDs based on sysDescr
	sysDescMap := map[string]*regexp.Regexp{
		"1.3.6.1.4.1.77.1.2.25": regexp.MustCompile("Windows"),
		"1.3.6.1.4.1.42.3.12.1.8": regexp.MustCompile("Sun"),
	}

	var matchingOIDs []string
	for oid, re := range sysDescMap {
		if re.MatchString(sysDescValue) {
			matchingOIDs = append(matchingOIDs, oid)
		}
	}

	if len(matchingOIDs) == 0 {
		log.Printf("Skipping unsupported sysDescr: '%s'", sysDescValue)
		return nil
	}

	var users []string
	for _, oid := range matchingOIDs {
		err := gosnmp.Default.Walk(oid, func(pdu gosnmp.SnmpPDU) error {
			users = append(users, string(pdu.Value.([]byte)))
			return nil
		})
		if err != nil {
			log.Printf("Error walking OID %s: %v", oid, err)
			continue
		}
	}

	if len(users) > 0 {
		sort.Strings(users)
		users = unique(users)
		log.Printf("Found %d users: %s", len(users), strings.Join(users, ", "))
	}

	return nil
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
	enumerator := NewSNMPUserEnumerator(ipAddress, 161) // Default SNMP port is 161
	enumerator.Run()
}
