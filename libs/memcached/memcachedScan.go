package memcached

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// MemcachedScanner represents a scanner for Memcached servers
type MemcachedScanner struct {
	Host    string
	Port    string
	Timeout time.Duration
}

// ServerInfo holds basic information about the Memcached server
type ServerInfo struct {
	Version string
	Uptime  string
}

// NewScanner creates a new MemcachedScanner with default settings
func NewScanner(host string) *MemcachedScanner {
	return &MemcachedScanner{
		Host:    host,
		Port:    "11211", // Default Memcached port
		Timeout: 5 * time.Second,
	}
}

// Connect establishes a connection to the Memcached server
func (m *MemcachedScanner) Connect() (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", m.Host+":"+m.Port, m.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Memcached server %s: %v", m.Host, err)
	}
	return conn, nil
}

// SendCommand sends a command to the Memcached server and returns the response
func (m *MemcachedScanner) SendCommand(conn net.Conn, command string) ([]string, error) {
	// Set a deadline for the connection
	conn.SetDeadline(time.Now().Add(m.Timeout))

	// Send the command
	_, err := conn.Write([]byte(command + "\r\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to send command: %v", err)
	}

	// Read the response
	var response []string
	reader := bufio.NewReader(conn)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("error reading response: %v", err)
		}

		// Trim the line and add it to the response
		line = strings.TrimSpace(line)

		// Check if we've reached the end of the response
		if line == "END" {
			break
		}

		response = append(response, line)
	}

	return response, nil
}

// GetStats retrieves all stats from the Memcached server
func (m *MemcachedScanner) GetStats() ([]string, error) {
	conn, err := m.Connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return m.SendCommand(conn, "stats")
}

// GetSettings retrieves all settings from the Memcached server
func (m *MemcachedScanner) GetSettings() ([]string, error) {
	conn, err := m.Connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return m.SendCommand(conn, "stats settings")
}

// GetServerInfo extracts version and uptime from stats
func (m *MemcachedScanner) GetServerInfo(stats []string) ServerInfo {
	info := ServerInfo{}

	for _, stat := range stats {
		if strings.HasPrefix(stat, "STAT version ") {
			info.Version = strings.TrimPrefix(stat, "STAT version ")
		} else if strings.HasPrefix(stat, "STAT uptime ") {
			uptime := strings.TrimPrefix(stat, "STAT uptime ")
			info.Uptime = uptime
		}
	}

	return info
}

// GetAllKeys retrieves all keys from the Memcached server
func (m *MemcachedScanner) GetAllKeys() (map[string]string, error) {
	conn, err := m.Connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// First, send the "stats items" command to get the slab IDs
	slabStats, err := m.SendCommand(conn, "stats items")
	if err != nil {
		return nil, fmt.Errorf("error getting slab stats: %v", err)
	}

	// Extract unique slab IDs
	slabIDs := make(map[string]bool)
	slabIDRegex := regexp.MustCompile(`items:(\d+):`)

	for _, stat := range slabStats {
		matches := slabIDRegex.FindStringSubmatch(stat)
		if len(matches) > 1 {
			slabIDs[matches[1]] = true
		}
	}

	// Get all keys for each slab
	allKeys := make(map[string]string)

	for slabID := range slabIDs {
		keys, err := m.dumpKeys(slabID)
		if err != nil {
			log.Printf("Warning: error dumping keys for slab %s: %v\n", slabID, err)
			continue
		}

				// For each key, get its value
		for _, key := range keys {
			value, err := m.getValue(key)
			if err != nil {
				log.Printf("Warning: error getting value for key %s: %v\n", key, err)
				continue
			}
			allKeys[key] = value
		}
	}

	return allKeys, nil
}

// dumpKeys retrieves all keys from a specific slab
func (m *MemcachedScanner) dumpKeys(slabID string) ([]string, error) {
	conn, err := m.Connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	response, err := m.SendCommand(conn, "stats cachedump "+slabID+" 0")
	if err != nil {
		return nil, err
	}

	keys := []string{}
	keyRegex := regexp.MustCompile(`ITEM (\S+) `)

	for _, line := range response {
		matches := keyRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			keys = append(keys, matches[1])
		}
	}

	return keys, nil
}

// getValue retrieves the value for a specific key
func (m *MemcachedScanner) getValue(key string) (string, error) {
	conn, err := m.Connect()
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Send the "get" command for the key
	_, err = conn.Write([]byte("get " + key + "\r\n"))
	if err != nil {
		return "", err
	}

	// Read the entire response including the value
	reader := bufio.NewReader(conn)
	var responseBuilder strings.Builder

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}

		responseBuilder.WriteString(line)

		// Check if we've reached the end of the response
		if strings.TrimSpace(line) == "END" {
			break
		}
	}

	return responseBuilder.String(), nil
}

// PrintServerInfo prints information about the Memcached server
func PrintServerInfo(info ServerInfo) {
	fmt.Println("Info:")
	uptimeSeconds, err := strconv.Atoi(info.Uptime)
	uptimeStr := formatUptime(info.Uptime)
	if err == nil {
		uptimeStr = fmt.Sprintf("%d", uptimeSeconds)
	}
	fmt.Printf("- Memcached %s (uptime %s)\n", info.Version, uptimeStr)
	fmt.Println()
}

// formatUptime converts uptime in seconds to a human-readable format
func formatUptime(uptime string) string {
	uptimeSeconds, err := strconv.Atoi(uptime)
	if err != nil {
		return uptime // Return raw if conversion fails
	}
	days := uptimeSeconds / 86400
	hours := (uptimeSeconds % 86400) / 3600
	minutes := (uptimeSeconds % 3600) / 60
	return fmt.Sprintf("%d days, %d hours, %d minutes", days, hours, minutes)
}

// PrintStats prints the stats in the specified format
func PrintStats(stats []string) {
	fmt.Println("Stats:")
	for _, stat := range stats {
		fmt.Printf("- %s\n", stat)
	}
	fmt.Println("END")
	fmt.Println()
}

// PrintSettings prints the settings in the specified format
func PrintSettings(settings []string) {
	fmt.Println("Stats Settings:")
	for _, setting := range settings {
		fmt.Printf("- %s\n", setting)
	}
	fmt.Println("END")
	fmt.Println()
}

// PrintKeys prints the keys and values in the specified format
func PrintKeys(keys map[string]string) {
	fmt.Println("Keys/Values:")
	if len(keys) == 0 {
		fmt.Println("- No keys found")
	} else {
		for key, value := range keys {
			fmt.Printf("- key: %s\n", key)
			fmt.Printf("- value: %q\n\n", value)
		}
	}
	fmt.Println()
}

// IsValidIP checks if the provided string is a valid IP address
func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// MemcachedScan performs the Memcached scan
func MemcachedScan(ipAddress string) {
	host := ipAddress

	if !IsValidIP(host) {
		log.Printf("Invalid IP address: %s\n", host)
		return
	}

	scanner := NewScanner(host)

	stats, err := scanner.GetStats()
	if err != nil {
		log.Printf("Error getting stats from %s: %v\n", host, err)
		return
	}

	serverInfo := scanner.GetServerInfo(stats)
	PrintServerInfo(serverInfo)

	PrintStats(stats)

	settings, err := scanner.GetSettings()
		if err != nil {
		log.Printf("Error getting settings from %s: %v\n", host, err)
	} else {
		PrintSettings(settings)
	}

	keys, err := scanner.GetAllKeys()
	if err != nil {
		log.Printf("Error getting keys from %s: %v\n", host, err)
	} else {
		PrintKeys(keys)
	}
}
