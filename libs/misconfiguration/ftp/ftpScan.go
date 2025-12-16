package ftp

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

func FTPScan(ipAddress string) {
	// FTP standard port
	port := 21
	
	// Format address based on whether it's IPv6 or IPv4
	// IPv6 addresses need to be enclosed in square brackets when specifying port
	var address string
	if strings.Contains(ipAddress, ":") && !strings.Contains(ipAddress, "[") {
		// This is likely an IPv6 address that needs to be properly formatted
		address = fmt.Sprintf("[%s]:%d", ipAddress, port)
	} else if strings.Contains(ipAddress, "[") && strings.Contains(ipAddress, "]") {
		// User already provided IPv6 with brackets, just add port
		address = fmt.Sprintf("%s:%d", ipAddress, port)
	} else {
		// Regular IPv4 address
		address = fmt.Sprintf("%s:%d", ipAddress, port)
	}

	// Connect to the FTP server with timeout
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
	} else {
		// Use a single connection for all operations when possible
		reader := bufio.NewReader(conn)
		
		// Read banner with longer timeout
		conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		banner, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading banner: %v\n", err)
			banner = "No banner received"
		} else {
			banner = strings.TrimSpace(banner)
			fmt.Printf("- banner: %s\n", banner)
			
			// Some servers send multiple banner lines
			for {
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				additionalLine, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				additionalLine = strings.TrimSpace(additionalLine)
				if strings.HasPrefix(additionalLine, "220-") || strings.HasPrefix(additionalLine, "220 ") {
					fmt.Printf("%s\n", additionalLine)
				} else {
					break
				}
			}
		}
		
		// Always check for anonymous login, regardless of previous errors
		allowed, response := checkAnonymousLogin(ipAddress, port, false)
		if allowed {
			fmt.Println("\n- Anonymous login: Allowed")
		} else {
			fmt.Println("\n- Anonymous login: Not allowed")
			if response != "" {
				fmt.Printf("%s\n", response)
			}
			
			// If regular anonymous login failed, try with TLS
			allowedTLS, responseTLS := checkAnonymousLogin(ipAddress, port, true)
			if allowedTLS {
				fmt.Println("\n- Anonymous login with TLS: Allowed")
			} else if strings.Contains(response, "SSL/TLS required") || 
					  strings.Contains(response, "TLS required") {
				fmt.Println("\n- Anonymous login with TLS: Not allowed")
				if responseTLS != "" {
					fmt.Printf("%s\n", responseTLS)
				}
			}
		}
		
		// First try without TLS
		requiresTLS := false
		features := []string{}
		featCommandUnderstood := true
		helpCommandUnderstood := true
		
		// Try to send FEAT command on regular connection
		fmt.Printf("\n- FEAT command:\n")
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write([]byte("FEAT\r\n"))
		if err == nil {
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			response, err := reader.ReadString('\n')
			
			// Check if this is a multiline response or an error
			if err == nil {
				response = strings.TrimSpace(response)
				
				// Check if we got a 550 SSL/TLS required response
				if strings.Contains(response, "SSL/TLS required") || 
				   strings.Contains(response, "TLS required") {
					fmt.Println("550 SSL/TLS required on the control channel")
					requiresTLS = true
				} else if strings.HasPrefix(response, "211-") {
					// This is the start of a multiline response, read the rest
					features = append(features, response)
					features = append(features, readMultilineResponseAfterFirstLine(reader, "211")...)
				} else if strings.Contains(response, "500") && strings.Contains(response, "command not understood") {
					// FEAT command not understood
					fmt.Printf("%s\n", response)
					featCommandUnderstood = false
				}
			}
			
			// If we got no features, check if TLS is required
			if len(features) == 0 && !requiresTLS && featCommandUnderstood {
				// Try to use AUTH TLS
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_, err = conn.Write([]byte("AUTH TLS\r\n"))
				if err == nil {
					response, err := reader.ReadString('\n')
					if err == nil {
						response = strings.TrimSpace(response)
						if strings.HasPrefix(response, "234") {
							fmt.Println("- Server requires TLS - attempting secure connection")
							requiresTLS = true
						}
					}
				}
			}
		}
		
		// Display features if any were found on the regular connection
		if len(features) > 0 {
			// Format the features similar to Shodan output
			fmt.Println("211-Features:")
			for _, feature := range features {
				// Skip the first and last lines (211- and 211 End)
				if !strings.HasPrefix(feature, "211-") && !strings.HasPrefix(feature, "211 ") {
					// Remove leading spaces and tabs for proper formatting
					fmt.Printf(" %s\n", strings.TrimSpace(feature))
				}
			}
			fmt.Println("211 End")
		}
		
		// Try to send HELP SITE command
		fmt.Printf("\n- HELP SITE command:\n")
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write([]byte("HELP SITE\r\n"))
		if err == nil {
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			response, err := reader.ReadString('\n')
			if err == nil {
				response = strings.TrimSpace(response)
				
				// Check if we got a 550 SSL/TLS required response
				if strings.Contains(response, "SSL/TLS required") || 
				   strings.Contains(response, "TLS required") {
					if !requiresTLS {  // Only display if not already shown
						fmt.Println("550 SSL/TLS required on the control channel")
						requiresTLS = true
					}
				} else if strings.HasPrefix(response, "214-") {
					// This is the start of a multiline response, read the rest
					siteCommands := append([]string{response}, readMultilineResponseAfterFirstLine(reader, "214")...)
					if len(siteCommands) > 0 {
						fmt.Println("214-The following SITE commands are recognized")
						for _, cmd := range siteCommands {
							if !strings.HasPrefix(cmd, "214") {
								fmt.Printf(" %s\n", cmd)
							}
						}
					}
				} else if strings.Contains(response, "500") && strings.Contains(response, "command not understood") {
					// HELP command not understood
					fmt.Printf("%s\n", response)
					helpCommandUnderstood = false
				}
			}
		}
		
		// Try to send regular HELP command if HELP SITE didn't indicate HELP is not understood
		fmt.Printf("\n- HELP command:\n")
		if helpCommandUnderstood {
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err = conn.Write([]byte("HELP\r\n"))
			if err == nil {
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				response, err := reader.ReadString('\n')
				if err == nil {
					response = strings.TrimSpace(response)
					
					// Check if we got a 550 SSL/TLS required response
					if strings.Contains(response, "SSL/TLS required") || 
					strings.Contains(response, "TLS required") {
						if !requiresTLS {  // Only display if not already shown
							fmt.Println("550 SSL/TLS required on the control channel")
							requiresTLS = true
						}
					} else if strings.HasPrefix(response, "214-") {
						// This is the start of a multiline response, read the rest
						cmds := append([]string{response}, readMultilineResponseAfterFirstLine(reader, "214")...)
						if len(cmds) > 0 {
							processAndPrintCommands(cmds)
						}
					} else if strings.Contains(response, "500") && strings.Contains(response, "command not understood") {
						// HELP command not understood
						fmt.Printf("%s\n", response)
						helpCommandUnderstood = false
					}
				}
			}
		}
		
		// Close the first connection
		conn.Close()
		
		// If TLS is required or we got no features and FEAT command was understood, try with TLS
		if requiresTLS || (len(features) == 0 && featCommandUnderstood) {
			tlsFeatures := getFeaturesWithTLS(ipAddress, port)
			if len(tlsFeatures) > 0 {
				// Format the features similar to Shodan output
				fmt.Println("211-Features:")
				for _, feature := range tlsFeatures {
					// Skip the first and last lines (211- and 211 End)
					if !strings.HasPrefix(feature, "211-") && !strings.HasPrefix(feature, "211 ") {
						// Remove leading spaces and tabs for proper formatting
						fmt.Printf(" %s\n", strings.TrimSpace(feature))
					}
				}
				fmt.Println("211 End")
			}
			
			// Try to get help commands via TLS if regular help command was understood
			if helpCommandUnderstood {
				tlsHelpCommands := getHelpCommandsWithTLS(ipAddress, port)
				if len(tlsHelpCommands) > 0 {
					processAndPrintCommands(tlsHelpCommands)
				}
			}
		}
	}
}

// Helper function to format address based on IP version
func formatAddress(ipAddress string, port int) string {
	// Check if it's an IPv6 address (contains colons but not already bracketed)
	if strings.Contains(ipAddress, ":") && !strings.HasPrefix(ipAddress, "[") {
		return fmt.Sprintf("[%s]:%d", ipAddress, port)
	} else if strings.HasPrefix(ipAddress, "[") && strings.HasSuffix(ipAddress, "]") {
		// Already has brackets but no port
		return fmt.Sprintf("%s:%d", ipAddress, port)
	} else if strings.Contains(ipAddress, "[") && strings.Contains(ipAddress, "]:") {
		// Already has brackets and port, return as is
		return ipAddress
	}
	// IPv4 address format
	return fmt.Sprintf("%s:%d", ipAddress, port)
}

func getFeaturesWithTLS(ipAddress string, port int) []string {
	address := formatAddress(ipAddress, port)
	features := []string{}
	
	// First establish a TCP connection
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		fmt.Printf("Failed to connect for TLS: %v\n", err)
	} else {
		defer conn.Close()
		
		// Read the banner
		reader := bufio.NewReader(conn)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, err = reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading banner for TLS: %v\n", err)
		} else {
			// Send AUTH TLS command
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err = conn.Write([]byte("AUTH TLS\r\n"))
			if err != nil {
				fmt.Printf("Error sending AUTH TLS: %v\n", err)
			} else {
				// Read the response
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				response, err := reader.ReadString('\n')
				if err != nil {
					fmt.Printf("Error reading AUTH TLS response: %v\n", err)
				} else {
					response = strings.TrimSpace(response)
					
					// Check if AUTH TLS was accepted
					if !strings.HasPrefix(response, "234") {
						fmt.Printf("AUTH TLS not accepted: %s\n", response)
					} else {
						// Upgrade to TLS
						tlsConn := tls.Client(conn, &tls.Config{
							InsecureSkipVerify: true, // Skip certificate verification for scanning purposes
						})
						defer tlsConn.Close()
						
						// Establish TLS handshake
						err = tlsConn.Handshake()
						if err != nil {
							fmt.Printf("TLS handshake failed: %v\n", err)
						} else {
							fmt.Println("\nTLS connection established successfully")
							
							// Create a new reader for the TLS connection
							tlsReader := bufio.NewReader(tlsConn)
							
							// Send the FEAT command over the secure connection
							tlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
							_, err = tlsConn.Write([]byte("FEAT\r\n"))
							if err != nil {
								fmt.Printf("Error sending FEAT over TLS: %v\n", err)
							} else {
								// Read the first line of the response
								tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
								firstLine, err := tlsReader.ReadString('\n')
								if err != nil {
									fmt.Printf("Error reading FEAT response over TLS: %v\n", err)
								} else {
									firstLine = strings.TrimSpace(firstLine)
									
									// Check if FEAT command is understood
									if strings.Contains(firstLine, "500") && strings.Contains(firstLine, "command not understood") {
										fmt.Printf("\n- %s\n", firstLine)
										return features
									}
									
									features = append(features, firstLine)
									
									if strings.HasPrefix(firstLine, "211-") {
										// Read the rest of the multiline response
										moreLines := readMultilineResponseAfterFirstLine(tlsReader, "211")
										features = append(features, moreLines...)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	
	return features
}

func getHelpCommandsWithTLS(ipAddress string, port int) []string {
	address := formatAddress(ipAddress, port)
	commands := []string{}
	
	// First establish a TCP connection
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		fmt.Printf("Failed to connect for TLS: %v\n", err)
	} else {
		defer conn.Close()
		
		// Read the banner
		reader := bufio.NewReader(conn)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, err = reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading banner for TLS help: %v\n", err)
		} else {
			// Send AUTH TLS command
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err = conn.Write([]byte("AUTH TLS\r\n"))
			if err != nil {
				fmt.Printf("Error sending AUTH TLS: %v\n", err)
			} else {
				// Read the response
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				response, err := reader.ReadString('\n')
				if err != nil {
					fmt.Printf("Error reading AUTH TLS response: %v\n", err)
				} else {
					response = strings.TrimSpace(response)
					
					// Check if AUTH TLS was accepted
					if !strings.HasPrefix(response, "234") {
						fmt.Printf("AUTH TLS not accepted for help: %s\n", response)
					} else {
						// Upgrade to TLS
						tlsConn := tls.Client(conn, &tls.Config{
							InsecureSkipVerify: true, // Skip certificate verification for scanning purposes
						})
						defer tlsConn.Close()
						
						// Establish TLS handshake
						err = tlsConn.Handshake()
						if err != nil {
							fmt.Printf("TLS handshake failed for help: %v\n", err)
						} else {
							// Create a new reader for the TLS connection
							tlsReader := bufio.NewReader(tlsConn)
							
							// Send the HELP command over the secure connection
							tlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
							_, err = tlsConn.Write([]byte("HELP\r\n"))
							if err != nil {
								fmt.Printf("Error sending HELP over TLS: %v\n", err)
							} else {
								// Read the first line of the response
								tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
								firstLine, err := tlsReader.ReadString('\n')
								if err != nil {
									fmt.Printf("Error reading HELP response over TLS: %v\n", err)
								} else {
									firstLine = strings.TrimSpace(firstLine)
									
									// Check if HELP command is understood
									if strings.Contains(firstLine, "500") && strings.Contains(firstLine, "command not understood") {
										fmt.Printf("\n- %s\n", firstLine)
										return commands
									}
									
									commands = append(commands, firstLine)
									
									if strings.HasPrefix(firstLine, "214-") {
										// Read the rest of the multiline response
										moreLines := readMultilineResponseAfterFirstLine(tlsReader, "214")
										commands = append(commands, moreLines...)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	
	return commands
}

// New function that reads multiline response after we've already read the first line
func readMultilineResponseAfterFirstLine(reader *bufio.Reader, codePrefix string) []string {
	var lines []string
	var endPrefix = codePrefix + " "
	
	for {
		// Set a reasonable timeout for each line
		time.Sleep(100 * time.Millisecond) // Small delay between reads
		
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		lines = append(lines, line)
		
		// Check if this is the end of the response
		if strings.HasPrefix(line, endPrefix) {
			break
		}
	}
	
	return lines
}

// Original function maintained for compatibility
func readMultilineResponse(reader *bufio.Reader, codePrefix string) []string {
	var lines []string
	var endPrefix = codePrefix + " "
	
	for {
		// Set a reasonable timeout for each line
		time.Sleep(100 * time.Millisecond) // Small delay between reads
		
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		lines = append(lines, line)
		
		// Check if this is the end of the response
		if strings.HasPrefix(line, endPrefix) {
			break
		}
	}
	
	return lines
}

func processAndPrintCommands(cmdLines []string) {
	fmt.Println("214-The following commands are recognized (* => unimplemented).")
	
	var commands []string
	for _, line := range cmdLines {
		if strings.HasPrefix(line, "214-") || strings.HasPrefix(line, "214 ") {
			continue
		}
		
		fields := strings.Fields(line)
		for _, field := range fields {
			if field != "" && field != "*" && field != "=>" {
				commands = append(commands, field)
			}
		}
	}
	
	// Display commands in rows
	for i := 0; i < len(commands); i += 9 {
		end := i + 9
		if end > len(commands) {
			end = len(commands)
		}
		fmt.Printf("   %s\n", strings.Join(commands[i:end], "    "))
	}
}

func checkAnonymousLogin(ip string, port int, useTLS bool) (bool, string) {
	address := formatAddress(ip, port)
	
	// Connect to FTP server with longer timeout
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return false, "Connection failed"
	}
	defer conn.Close()
	
	// Read welcome message
	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	
	// Read all banner lines
	for {
		_, err := reader.ReadString('\n')
		if err != nil {
			return false, "Error reading banner"
		}
		
		// Try to read another line with short timeout
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, err = reader.ReadString('\n')
		if err != nil {
			// No more banner lines
			break
		}
	}
	
	// If TLS is required, upgrade the connection
	var tlsConn *tls.Conn
	if useTLS {
		// Send AUTH TLS command
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write([]byte("AUTH TLS\r\n"))
		if err != nil {
			return false, "Error sending AUTH TLS"
		}
		
		// Read the response
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		response, err := reader.ReadString('\n')
		if err != nil {
			return false, "Error reading AUTH TLS response"
		}
		response = strings.TrimSpace(response)
		
		// Check if AUTH TLS was accepted
		if !strings.HasPrefix(response, "234") {
			return false, fmt.Sprintf("AUTH TLS not accepted: %s", response)
		}
		
		// Upgrade to TLS
		tlsConn = tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true, // Skip certificate verification for scanning purposes
		})
		
		// Establish TLS handshake
		err = tlsConn.Handshake()
		if err != nil {
			return false, fmt.Sprintf("TLS handshake failed: %v", err)
		}
		
		// Use the TLS connection for the rest of the commands
		reader = bufio.NewReader(tlsConn)
	}
	
	// Reset deadline for commands
	if useTLS {
		tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	} else {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	}
	
	// Try anonymous login
	if useTLS {
		fmt.Fprintf(tlsConn, "USER anonymous\r\n")
	} else {
		fmt.Fprintf(conn, "USER anonymous\r\n")
	}
	
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, "Error sending USER command"
	}
	
	response = strings.TrimSpace(response)
	
	// Check response codes:
	// 530: Not allowed / Error
	// 331: Password required
	// 230: Login successful without password
	if strings.HasPrefix(response, "530") {
		// Check if this is a TLS required message
		if strings.Contains(response, "SSL/TLS required") || 
		   strings.Contains(response, "TLS required") {
			return false, "550 SSL/TLS required on the control channel"
		}
		return false, response
	}
	
	if !strings.HasPrefix(response, "331") {
		// Unexpected response
		return false, response
	}
	
	// Send password
	if useTLS {
		fmt.Fprintf(tlsConn, "PASS anonymous@example.com\r\n")
		tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	} else {
		fmt.Fprintf(conn, "PASS anonymous@example.com\r\n")
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	}
	
	response, err = reader.ReadString('\n')
	if err != nil {
		return false, "Error sending PASS command"
	}
	
	response = strings.TrimSpace(response)
	
	// 230 code indicates successful login
	return strings.HasPrefix(response, "230"), response
}
