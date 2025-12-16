package smb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"
)

// Constants for SMB protocol
const (
	// SMB Command codes
	SMB_COM_NEGOTIATE       = 0x72
	SMB_COM_SESSION_SETUP   = 0x73
	SMB_COM_TREE_CONNECT    = 0x75
	SMB_COM_TRANSACTION     = 0x25
	SMB_COM_LOGOFF          = 0x74
	SMB_COM_TREE_DISCONNECT = 0x71

	// NTLMSSP message types
	NTLMSSP_NEGOTIATE = 0x00000001
	NTLMSSP_CHALLENGE = 0x00000002
	NTLMSSP_AUTH      = 0x00000003

	// Common port for SMB
	SMB_PORT = 445
)

// SMBClient represents a client that connects to an SMB server
type SMBClient struct {
	Address string
	Port    int
	Conn    net.Conn
	SessionID uint64
	TreeID    uint32
	UserID    uint16
}

// NewSMBClient creates a new SMB client
func NewSMBClient(address string, port int) *SMBClient {
	return &SMBClient{
		Address: address,
		Port:    port,
	}
}

// Connect establishes a connection to the SMB server
func (client *SMBClient) Connect() error {
	address := fmt.Sprintf("%s:%d", client.Address, client.Port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return err
	}
	client.Conn = conn
	return nil
}

// Close closes the connection to the SMB server
func (client *SMBClient) Close() {
	if client.Conn != nil {
		client.Conn.Close()
	}
}

// SMB Header structure
type SMBHeader struct {
	Protocol    [4]byte  // 0xFF, 'S', 'M', 'B'
	Command     byte
	Status      uint32
	Flags       byte
	Flags2      uint16
	PIDHigh     uint16
	SecuritySig [8]byte
	Reserved    uint16
	TreeID      uint16
	ProcessID   uint16
	UserID      uint16
	MultiplexID uint16
}

// NewSMB2Header creates a new SMB2 header
func NewSMBHeader(command byte) *SMBHeader {
	header := &SMBHeader{
		Command:     command,
		Flags:       0x18,       // Case sensitive, canonicalized pathnames
		Flags2:      0xC803,     // Unicode, NT error codes, long names allowed, extended security
		ProcessID:   0xFEFF,     // Default process ID
		MultiplexID: 0x0001,     // Multiplex ID
	}
	copy(header.Protocol[:], []byte{0xFF, 'S', 'M', 'B'})
	return header
}

// Serialize converts an SMB header to bytes
func (h *SMBHeader) Serialize() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, h.Protocol)
	binary.Write(buf, binary.LittleEndian, h.Command)
	binary.Write(buf, binary.LittleEndian, h.Status)
	binary.Write(buf, binary.LittleEndian, h.Flags)
	binary.Write(buf, binary.LittleEndian, h.Flags2)
	binary.Write(buf, binary.LittleEndian, h.PIDHigh)
	binary.Write(buf, binary.LittleEndian, h.SecuritySig)
	binary.Write(buf, binary.LittleEndian, h.Reserved)
	binary.Write(buf, binary.LittleEndian, h.TreeID)
	binary.Write(buf, binary.LittleEndian, h.ProcessID)
	binary.Write(buf, binary.LittleEndian, h.UserID)
	binary.Write(buf, binary.LittleEndian, h.MultiplexID)
	return buf.Bytes()
}

// ParseSMBHeader parses SMB header from raw bytes
func ParseSMBHeader(data []byte) (*SMBHeader, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("data too short for SMB header")
	}
	
	header := &SMBHeader{}
	buf := bytes.NewReader(data)
	
	binary.Read(buf, binary.LittleEndian, &header.Protocol)
	binary.Read(buf, binary.LittleEndian, &header.Command)
	binary.Read(buf, binary.LittleEndian, &header.Status)
	binary.Read(buf, binary.LittleEndian, &header.Flags)
	binary.Read(buf, binary.LittleEndian, &header.Flags2)
	binary.Read(buf, binary.LittleEndian, &header.PIDHigh)
	binary.Read(buf, binary.LittleEndian, &header.SecuritySig)
	binary.Read(buf, binary.LittleEndian, &header.Reserved)
	binary.Read(buf, binary.LittleEndian, &header.TreeID)
	binary.Read(buf, binary.LittleEndian, &header.ProcessID)
	binary.Read(buf, binary.LittleEndian, &header.UserID)
	binary.Read(buf, binary.LittleEndian, &header.MultiplexID)
	
	return header, nil
}

// CreateNegotiateRequest creates an SMB negotiate request packet
func CreateNegotiateRequest() []byte {
	header := NewSMBHeader(SMB_COM_NEGOTIATE)
	
	// Build negotiate protocol request
	dialects := []string{"NT LM 0.12"}
	dialectBytes := new(bytes.Buffer)
	
	// WordCount is zero for negotiate
	dialectBytes.WriteByte(0)
	
	// Calculate byte count (2 bytes per dialect string + null byte)
	byteCount := 0
	for _, dialect := range dialects {
		byteCount += len(dialect) + 2
	}
	
	binary.Write(dialectBytes, binary.LittleEndian, uint16(byteCount))
	
	// Add dialects
	for _, dialect := range dialects {
		dialectBytes.WriteByte(0x02) // Dialect buffer format
		dialectBytes.WriteString(dialect)
		dialectBytes.WriteByte(0x00) // Null terminator
	}
	
	// Combine header and negotiate data
	packet := new(bytes.Buffer)
	
	// NetBIOS Session Service header (4 bytes)
	// Type: Session Message (0x00)
	// Length: Length of SMB packet
	packetLength := uint32(len(header.Serialize()) + dialectBytes.Len())
	packet.WriteByte(0x00)
	packet.WriteByte(0x00)
	packet.WriteByte(byte((packetLength >> 8) & 0xFF))
	packet.WriteByte(byte(packetLength & 0xFF))
	
	// Write SMB header
	packet.Write(header.Serialize())
	
	// Write dialect data
	packet.Write(dialectBytes.Bytes())
	
	return packet.Bytes()
}

// CreateSessionSetupRequest creates an SMB session setup request
func CreateSessionSetupRequest(username string) []byte {
	header := NewSMBHeader(SMB_COM_SESSION_SETUP)
	
	buf := new(bytes.Buffer)
	
	// WordCount (number of parameter words) = 13
	buf.WriteByte(13)
	
	// AndXCommand: No further commands
	buf.WriteByte(0xFF)
	
	// AndXReserved
	buf.WriteByte(0x00)
	
	// AndXOffset: Will be filled later
	binary.Write(buf, binary.LittleEndian, uint16(0))
	
	// MaxBufferSize
	binary.Write(buf, binary.LittleEndian, uint16(4356))
	
	// MaxMpxCount
	binary.Write(buf, binary.LittleEndian, uint16(50))
	
	// VcNumber
	binary.Write(buf, binary.LittleEndian, uint16(0))
	
	// SessionKey
	binary.Write(buf, binary.LittleEndian, uint32(0))
	
	// ANSI Password Length (anonymous login, so 1 byte)
	binary.Write(buf, binary.LittleEndian, uint16(1))
	
	// Unicode Password Length (none for anonymous)
	binary.Write(buf, binary.LittleEndian, uint16(0))
	
	// Reserved
	binary.Write(buf, binary.LittleEndian, uint32(0))
	
	// Capabilities
	binary.Write(buf, binary.LittleEndian, uint32(0x000000D4))
	
	// Calculate byte count
	// Account name + domain name (null-terminated) + native OS + native LAN manager
	accountName := username
	domain := "WORKGROUP"
	nativeOS := "Unix"
	nativeLanMan := "Samba"
	
	// We add padding to ensure proper alignment for Unicode strings
	byteCount := 1 + len(accountName) + 1 + len(domain) + 1 + len(nativeOS) + 1 + len(nativeLanMan) + 1 + 2 // +2 for alignment
	
	// ByteCount
	binary.Write(buf, binary.LittleEndian, uint16(byteCount))
	
	// Anonymous password (1 byte of 0)
	buf.WriteByte(0x00)
	
	// Account Name (null-terminated)
	buf.WriteString(accountName)
	buf.WriteByte(0x00)
	
	// Domain Name (null-terminated)
	buf.WriteString(domain)
	buf.WriteByte(0x00)
	
	// Native OS (null-terminated)
	buf.WriteString(nativeOS)
	buf.WriteByte(0x00)
	
	// Native LAN Manager (null-terminated)
	buf.WriteString(nativeLanMan)
	buf.WriteByte(0x00)
	
	// Extra byte for alignment
	buf.WriteByte(0x00)
	
	// Combine header and session setup data
	packet := new(bytes.Buffer)
	
	// NetBIOS Session Service header (4 bytes)
	packetLength := uint32(len(header.Serialize()) + buf.Len())
	packet.WriteByte(0x00)
	packet.WriteByte(0x00)
	packet.WriteByte(byte((packetLength >> 8) & 0xFF))
	packet.WriteByte(byte(packetLength & 0xFF))
	
	// Write SMB header
	packet.Write(header.Serialize())
	
	// Write session setup data
	packet.Write(buf.Bytes())
	
	return packet.Bytes()
}

// SendReceive sends a packet and receives a response
func (client *SMBClient) SendReceive(packet []byte) ([]byte, error) {
	// Send the packet
	_, err := client.Conn.Write(packet)
	if err != nil {
		return nil, fmt.Errorf("error sending packet: %v", err)
	}
	
	// Receive NetBIOS header (4 bytes)
	nbHeader := make([]byte, 4)
	_, err = client.Conn.Read(nbHeader)
	if err != nil {
		return nil, fmt.Errorf("error reading NetBIOS header: %v", err)
	}
	
	// Calculate packet length from NetBIOS header
	packetLength := (uint32(nbHeader[2]) << 8) | uint32(nbHeader[3])
	
	// Read the SMB packet
	response := make([]byte, packetLength)
	bytesRead := 0
	for bytesRead < int(packetLength) {
		n, err := client.Conn.Read(response[bytesRead:])
		if err != nil {
			return nil, fmt.Errorf("error reading SMB response: %v", err)
		}
		bytesRead += n
	}
	
	return response, nil
}

// EnumerateUsers attempts to enumerate users on the SMB server
func (client *SMBClient) EnumerateUsers(userList []string) ([]string, error) {
	var validUsers []string
	
	// Negotiate protocol first
	negotiatePacket := CreateNegotiateRequest()
	response, err := client.SendReceive(negotiatePacket)
	if err != nil {
		return nil, fmt.Errorf("negotiate protocol failed: %v", err)
	}
	
	smbHeader, err := ParseSMBHeader(response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse negotiate response: %v", err)
	}
	
	// Check if negotiate was successful
	if smbHeader.Status != 0 {
		return nil, fmt.Errorf("negotiate protocol failed with status: 0x%08x", smbHeader.Status)
	}
	
	// Protocol negotiation successful
	
	// Try to authenticate with each username
	for _, username := range userList {
		// Trying username
		
		sessionSetupPacket := CreateSessionSetupRequest(username)
		response, err := client.SendReceive(sessionSetupPacket)
		if err != nil {
			continue
		}
		
		smbHeader, err := ParseSMBHeader(response)
		if err != nil {
			continue
		}
		
		// Status code 0xC0000022 = NT_STATUS_ACCESS_DENIED means the user exists but password is wrong
		// Status code 0xC000006D = NT_STATUS_LOGON_FAILURE also indicates user exists but auth failed
		// Status code 0xC0000064 = NT_STATUS_NO_SUCH_USER means user doesn't exist
		
		statusCode := smbHeader.Status
		
		switch statusCode {
		case 0: // Success
			validUsers = append(validUsers, username)
		case 0xC0000022, 0xC000006D: // NT_STATUS_ACCESS_DENIED or NT_STATUS_LOGON_FAILURE 
			validUsers = append(validUsers, username)
		case 0xC0000064: // NT_STATUS_NO_SUCH_USER
			// Not a valid user, do nothing
		default:
			// Unknown status code, do nothing
		}
	}
	
	return validUsers, nil
}

// main function to execute the program
func SMBEnumUsers(ipAddress string) {
	
	client := NewSMBClient(ipAddress, SMB_PORT)
	err := client.Connect()
	if err != nil {
		fmt.Println("Error connecting to SMB server:", err)
		os.Exit(1)
	}
	defer client.Close()
	
	fmt.Println("Successfully connected to SMB server at", ipAddress)
	
	// Define a list of common usernames to check
	// You can expand this list or load it from a file
	userList := []string{
		"administrator", "admin", "user", "guest", "root",
		"test", "webadmin", "sysadmin", "netadmin", "operator",
		"backup", "manager", "staff", "support", "info",
		"helpdesk", "service", "tech", "demo", "anonymous",
		"adm", "owner", "supervisor", "director", "executive",
		"controller", "auditor", "finance", "hr", "accounting",
		"sales", "marketing", "development", "research", "design",
		"it", "security", "network", "system", "database",
		"dba", "oracle", "sql", "mysql", "postgres",
		"ubuntu", "centos", "redhat", "debian", "fedora",
		"windows", "linux", "unix", "macos", "solaris",
		"ftp", "www", "mail", "smtp", "pop3",
		"imap", "dns", "dhcp", "ldap", "proxy",
		"printer", "scanner", "library", "archive", "storage",
		"backup", "restore", "recovery", "monitor", "logger",
		"tomcat", "apache", "nginx", "iis", "weblogic",
		"websphere", "jboss", "jenkins", "gitlab", "github",
		"svn", "git", "mercurial", "cvs", "bamboo",
		"jira", "confluence", "sharepoint", "wordpress", "drupal",
		"magento", "shopify", "prestashop", "woocommerce", "opencart",
		"odoo", "sap", "oracle", "dynamics", "salesforce",
		"zendesk", "servicenow", "remedy", "quickbooks", "sage",
		"aduser", "localadmin", "domainadmin", "poweruser", "userlocal",
		"temp", "tempuser", "trainee", "intern", "contractor",
		"consultant", "partner", "vendor", "client", "customer",
	}

	validUsers, err := client.EnumerateUsers(userList)
	if err != nil {
		fmt.Println("Error during user enumeration:", err)
		os.Exit(1)
	}
	
	if len(validUsers) > 0 {
		fmt.Println("\nValid Usernames: ")
		for _, user := range validUsers {
			fmt.Printf("- %s\n", user)
		}
	} else {
		fmt.Println("No username was found")
	}
}
