package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

const soapTemplate = `<?xml version="1.0" encoding="utf-8"?>
<Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xmlns:xsd="http://www.w3.org/2001/XMLSchema"
          xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
          xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
          xmlns="http://www.w3.org/2003/05/soap-envelope">
  <Header>
    <a:Action>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_PowerManagementService/RequestPowerStateChange</a:Action>
    <a:To>/wsman</a:To>
    <w:ResourceURI>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_PowerManagementService</w:ResourceURI>
    <a:MessageID>1</a:MessageID>
    <a:ReplyTo>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <w:OperationTimeout>PT60S</w:OperationTimeout>
  </Header>
  <Body>
    <r:RequestPowerStateChange_INPUT xmlns:r="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_PowerManagementService">
      <r:PowerState>%d</r:PowerState>
      <r:ManagedElement>
        <Address xmlns="http://schemas.xmlsoap.org/ws/2004/08/addressing">http://schemas.xmlsoap.org/ws/2004/08/addressing</Address>
        <ReferenceParameters xmlns="http://schemas.xmlsoap.org/ws/2004/08/addressing">
          <ResourceURI xmlns="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ComputerSystem</ResourceURI>
          <SelectorSet xmlns="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
            <Selector Name="CreationClassName">CIM_ComputerSystem</Selector>
            <Selector Name="Name">ManagedSystem</Selector>
          </SelectorSet>
        </ReferenceParameters>
      </r:ManagedElement>
    </r:RequestPowerStateChange_INPUT>
  </Body>
</Envelope>`

// KDF / cipher constants.
const (
	scryptN = 32768
	scryptR = 8
	scryptP = 1
	saltLen = 16
	keyLen  = 32
	nonceLen = 12
)

// defaultConfigPath is the default location for the encrypted config file.
var defaultConfigPath = "~/.amt-power/config"

// configFile represents the on-disk encrypted config (line-based key = value).
type configFile struct {
	KDF        string
	N, R, P    int
	Salt       []byte // raw bytes; hex-encoded in the file
	Nonce      []byte // raw bytes; hex-encoded in the file
	Ciphertext []byte // raw bytes; hex-encoded in the file
	User       string
	Port       int
}

// expandPath expands a leading "~" to the user's home directory.
func expandPath(p string) (string, error) {
	if p == "" || p[0] != '~' {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, p[1:]), nil
}

// deriveKey derives a 32-byte AES key from a passphrase and salt using scrypt.
func deriveKey(passphrase string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, keyLen)
}

// encryptPassword generates a fresh salt + nonce and encrypts the password with AES-256-GCM.
func encryptPassword(password, passphrase string) (*configFile, error) {
	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	defer func() { for i := range key { key[i] = 0 } }()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &configFile{
		KDF:        "scrypt",
		N:          scryptN,
		R:          scryptR,
		P:          scryptP,
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: gcm.Seal(nil, nonce, []byte(password), nil),
	}, nil
}

// decryptPassword derives the key from the passphrase + stored salt and decrypts the config.
func decryptPassword(passphrase string, cfg *configFile) (string, error) {
	if len(cfg.Salt) != saltLen || len(cfg.Nonce) != nonceLen || len(cfg.Ciphertext) == 0 {
		return "", fmt.Errorf("invalid config: missing or corrupt crypto fields")
	}

	key, err := deriveKey(passphrase, cfg.Salt)
	if err != nil {
		return "", fmt.Errorf("failed to derive key: %w", err)
	}
	defer func() { for i := range key { key[i] = 0 } }()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	pt, err := gcm.Open(nil, cfg.Nonce, cfg.Ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: wrong passphrase or corrupt config")
	}
	return string(pt), nil
}

// writeConfigFile writes the config to disk in line-based key = value format.
func writeConfigFile(path string, cfg *configFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	var sb strings.Builder
	sb.WriteString("# amt-power encrypted config\n")
	sb.WriteString("# generated by: amt-power pass set\n")
	sb.WriteString(fmt.Sprintf("kdf = %s\n", cfg.KDF))
	sb.WriteString(fmt.Sprintf("n = %d\n", cfg.N))
	sb.WriteString(fmt.Sprintf("r = %d\n", cfg.R))
	sb.WriteString(fmt.Sprintf("p = %d\n", cfg.P))
	sb.WriteString(fmt.Sprintf("salt = %s\n", hex.EncodeToString(cfg.Salt)))
	sb.WriteString(fmt.Sprintf("nonce = %s\n", hex.EncodeToString(cfg.Nonce)))
	sb.WriteString(fmt.Sprintf("ciphertext = %s\n", hex.EncodeToString(cfg.Ciphertext)))
	if cfg.User != "" {
		sb.WriteString(fmt.Sprintf("user = %s\n", cfg.User))
	}
	if cfg.Port > 0 {
		sb.WriteString(fmt.Sprintf("port = %d\n", cfg.Port))
	}

	if err := os.WriteFile(path, []byte(sb.String()), 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	return nil
}

// readConfigFile parses the config file and returns the decoded fields.
func readConfigFile(path string) (*configFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	cfg := &configFile{User: "admin", Port: 16992}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid line: %s", line)
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "kdf":
			cfg.KDF = val
		case "n":
			if cfg.N, err = strconv.Atoi(val); err != nil {
				return nil, fmt.Errorf("invalid n value: %s", val)
			}
		case "r":
			if cfg.R, err = strconv.Atoi(val); err != nil {
				return nil, fmt.Errorf("invalid r value: %s", val)
			}
		case "p":
			if cfg.P, err = strconv.Atoi(val); err != nil {
				return nil, fmt.Errorf("invalid p value: %s", val)
			}
		case "salt":
			if cfg.Salt, err = hex.DecodeString(val); err != nil {
				return nil, fmt.Errorf("invalid salt: must be hex-encoded")
			}
		case "nonce":
			if cfg.Nonce, err = hex.DecodeString(val); err != nil {
				return nil, fmt.Errorf("invalid nonce: must be hex-encoded")
			}
		case "ciphertext":
			if cfg.Ciphertext, err = hex.DecodeString(val); err != nil {
				return nil, fmt.Errorf("invalid ciphertext: must be hex-encoded")
			}
		case "user":
			cfg.User = val
		case "port":
			if cfg.Port, err = strconv.Atoi(val); err != nil {
				return nil, fmt.Errorf("invalid port value: %s", val)
			}
		default:
			return nil, fmt.Errorf("unknown config key: %s", key)
		}
	}

	if cfg.KDF != "scrypt" {
		return nil, fmt.Errorf("unsupported kdf: %s (only scrypt is supported)", cfg.KDF)
	}
	return cfg, nil
}

// resolveSecret resolves a secret from flag, environment, or hidden prompt (in that order).
func resolveSecret(flagValue, envVar, label string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if v := os.Getenv(envVar); v != "" {
		return v, nil
	}

	// Interactive hidden prompt
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(os.Stderr, "Enter %s: ", label)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("failed to read %s: %w", label, err)
		}
		return string(b), nil
	}

	return "", fmt.Errorf("cannot prompt: provide %s via -%s flag or environment variable %s", label, label, envVar)
}

func md5Hex(data string) string {
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

func parseDigestHeader(header string) map[string]string {
	result := make(map[string]string)
	if !strings.HasPrefix(header, "Digest ") {
		return result
	}
	parts := strings.Split(header[7:], ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			k := strings.TrimSpace(kv[0])
			v := strings.Trim(strings.TrimSpace(kv[1]), `"`)
			result[k] = v
		}
	}
	return result
}

func buildDigestAuth(username, password, method, uri string, challenge map[string]string) string {
	realm := challenge["realm"]
	nonce := challenge["nonce"]
	qop := challenge["qop"]

	ha1 := md5Hex(fmt.Sprintf("%s:%s:%s", username, realm, password))
	ha2 := md5Hex(fmt.Sprintf("%s:%s", method, uri))

	if strings.Contains(qop, "auth") {
		cnonceBytes := make([]byte, 8)
		rand.Read(cnonceBytes)
		cnonce := hex.EncodeToString(cnonceBytes)
		nc := "00000001"

		response := md5Hex(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, nonce, nc, cnonce, "auth", ha2))
		return fmt.Sprintf(
			`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", qop=auth, nc=%s, cnonce="%s"`,
			username, realm, nonce, uri, response, nc, cnonce,
		)
	}

	response := md5Hex(fmt.Sprintf("%s:%s:%s", ha1, nonce, ha2))
	return fmt.Sprintf(
		`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		username, realm, nonce, uri, response,
	)
}

type powerAction struct {
	state int
	desc  string
}

// powerActions maps CLI action names to DMTF CIM RequestPowerStateChange codes.
// Codes verified against Intel AMT CIM_PowerManagementService:
//
//	2  = Power On
//	5  = Power Cycle (off hard, then on)
//	8  = Power Off - Hard
//	12 = Power Off - Soft Graceful (orderly OS shutdown)
//	14 = Master Bus Reset Graceful (orderly OS reboot)
//
// Graceful actions (12/14) are only honored when the platform advertises them
// in CIM_AssociatedPowerManagementService.AvailableRequestedPowerStates;
// otherwise use the -hard variants.
var powerActions = map[string]powerAction{
	"on":          {2, "power on"},
	"off":         {12, "graceful power off (soft)"},
	"off-hard":    {8, "hard power off"},
	"reboot":      {14, "graceful reboot (soft reset)"},
	"reboot-hard": {5, "hard power cycle"},
}

func requestPowerState(ip, username, password string, port int, act powerAction) error {
	endpoint := fmt.Sprintf("http://%s:%d/wsman", ip, port)
	uri := "/wsman"
	soapBody := fmt.Sprintf(soapTemplate, act.state)
	client := &http.Client{Timeout: 15 * time.Second}

	// 1. Initial unauthenticated request to obtain 401 challenge
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(soapBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("expected 401 Unauthorized, got status %d", resp.StatusCode)
	}

	authHeader := resp.Header.Get("WWW-Authenticate")
	if authHeader == "" {
		return fmt.Errorf("missing WWW-Authenticate header in response")
	}

	challenge := parseDigestHeader(authHeader)

	// 2. Authenticated request with Digest Authorization header
	authValue := buildDigestAuth(username, password, http.MethodPost, uri, challenge)

	reqAuth, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(soapBody))
	if err != nil {
		return fmt.Errorf("failed to create authenticated request: %w", err)
	}
	reqAuth.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	reqAuth.Header.Set("Authorization", authValue)

	respAuth, err := client.Do(reqAuth)
	if err != nil {
		return fmt.Errorf("failed to send authenticated request: %w", err)
	}
	defer respAuth.Body.Close()

	body, _ := io.ReadAll(respAuth.Body)
	bodyStr := string(body)

	if respAuth.StatusCode != http.StatusOK {
		return fmt.Errorf("AMT returned status %d: %s", respAuth.StatusCode, bodyStr)
	}

	var returnVal string
	if idx := strings.Index(bodyStr, "ReturnValue>"); idx != -1 {
		endIdx := strings.Index(bodyStr[idx:], "</")
		if endIdx != -1 {
			returnVal = bodyStr[idx+len("ReturnValue>") : idx+endIdx]
		}
	}

	if returnVal == "0" || returnVal == "4096" {
		fmt.Printf("%s executed successfully on %s (PowerState=%d, ReturnValue=%s)\n", act.desc, ip, act.state, returnVal)
		return nil
	}

	return fmt.Errorf("command returned error (ReturnValue: %s): %s", returnVal, bodyStr)
}

// passUsage prints the usage for the pass subcommand.
func passUsage() {
	fmt.Fprintln(os.Stderr, "Usage: amt-power pass <command>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  set     Create or update the encrypted config file")
	fmt.Fprintln(os.Stderr, "  verify  Test that the config file decrypts correctly")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Environment variables:")
	fmt.Fprintln(os.Stderr, "  AMT_PASSPHRASE  Passphrase for config encryption/decryption")
}

// runPassSet handles the "pass set" subcommand.
func runPassSet(args []string) {
	fs := flag.NewFlagSet("pass set", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "Path to config file")
	user := fs.String("user", "admin", "Intel AMT username to store in config")
	port := fs.Int("port", 16992, "Intel AMT port to store in config")
	passphraseFlag := fs.String("passphrase", "", "Passphrase (or use AMT_PASSPHRASE env var)")
	passwordFlag := fs.String("password", "", "AMT password (or use AMT_PASSWORD env var)")
	fs.Parse(args)

	// Resolve passphrase and password
	passphrase, err := resolveSecret(*passphraseFlag, "AMT_PASSPHRASE", "passphrase")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	password, err := resolveSecret(*passwordFlag, "AMT_PASSWORD", "AMT password")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(passphrase) < 8 {
		fmt.Fprintln(os.Stderr, "Error: passphrase must be at least 8 characters")
		os.Exit(1)
	}

	// Encrypt
	cfg, err := encryptPassword(password, passphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	cfg.User = *user
	cfg.Port = *port

	// Resolve path and write
	path, err := expandPath(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if err := writeConfigFile(path, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Config written to %s (scrypt + AES-256-GCM)\n", path)
}

// runPassVerify handles the "pass verify" subcommand.
func runPassVerify(args []string) {
	fs := flag.NewFlagSet("pass verify", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "Path to config file")
	passphraseFlag := fs.String("passphrase", "", "Passphrase (or use AMT_PASSPHRASE env var)")
	fs.Parse(args)

	passphrase, err := resolveSecret(*passphraseFlag, "AMT_PASSPHRASE", "passphrase")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	path, err := expandPath(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	cfg, err := readConfigFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if _, err := decryptPassword(passphrase, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("OK: config decrypts successfully")
}

// runPassCommand dispatches to "pass set" or "pass verify".
func runPassCommand(args []string) {
	if len(args) == 0 {
		passUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "set":
		runPassSet(args[1:])
	case "verify":
		runPassVerify(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown pass command %q\n", args[0])
		passUsage()
		os.Exit(1)
	}
}

func main() {
	// Subcommand dispatch: amt-power pass ...
	if len(os.Args) > 1 && os.Args[1] == "pass" {
		runPassCommand(os.Args[2:])
		return
	}

	// Normal mode: amt-power -ip ... -action ...
	ip := flag.String("ip", "", "Target Intel AMT IP address")
	userFlag := flag.String("user", "admin", "Intel AMT username")
	portFlag := flag.Int("port", 16992, "Intel AMT port (default 16992)")
	action := flag.String("action", "on", "Power action: on, off, off-hard, reboot, reboot-hard (default: on)")
	configPath := flag.String("config", defaultConfigPath, "Path to encrypted config file")
	passphraseFlag := flag.String("passphrase", "", "Passphrase to decrypt config (or use AMT_PASSPHRASE env var)")

	flag.Parse()

	if *ip == "" {
		fmt.Fprintln(os.Stderr, "Error: -ip flag is required")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage: amt-power -ip <IP> [-action on|off|off-hard|reboot|reboot-hard] [-user admin] [-port 16992] [-passphrase <passphrase>]")
		fmt.Fprintf(os.Stderr, "       amt-power pass set [-config %s] [-passphrase <passphrase>]\n", defaultConfigPath)
		os.Exit(1)
	}

	// Resolve password from config or legacy env var
	var pass string
	path, _ := expandPath(*configPath)

	_, configExists := os.Stat(path)
	if configExists == nil {
		// Config file exists: use it
		passphrase, err := resolveSecret(*passphraseFlag, "AMT_PASSPHRASE", "passphrase")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		cfg, err := readConfigFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		pass, err = decryptPassword(passphrase, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		// Apply config defaults for user/port if not explicitly set on CLI
		userExplicit := false
		portExplicit := false
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "user" { userExplicit = true }
			if f.Name == "port" { portExplicit = true }
		})
		if !userExplicit && cfg.User != "" && cfg.User != "admin" {
			*userFlag = cfg.User
		}
		if !portExplicit && cfg.Port > 0 && cfg.Port != 16992 {
			*portFlag = cfg.Port
		}
	} else if v := os.Getenv("AMT_PASSWORD"); v != "" {
		// Legacy fallback
		fmt.Fprintln(os.Stderr, "Warning: AMT_PASSWORD is deprecated; run 'amt-power pass set' to create an encrypted config")
		pass = v
	} else {
		fmt.Fprintln(os.Stderr, "Error: no password source: create an encrypted config with 'amt-power pass set'")
		fmt.Fprintln(os.Stderr, "       (or set AMT_PASSWORD, which is deprecated)")
		os.Exit(1)
	}

	act, ok := powerActions[strings.ToLower(*action)]
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: invalid action %q (valid: on, off, off-hard, reboot, reboot-hard)\n", *action)
		os.Exit(1)
	}

	if err := requestPowerState(*ip, *userFlag, pass, *portFlag, act); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
