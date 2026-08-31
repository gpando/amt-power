package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
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

func main() {
	ip := flag.String("ip", "", "Target Intel AMT IP address")
	user := flag.String("user", "admin", "Intel AMT username")
	port := flag.Int("port", 16992, "Intel AMT port (default 16992)")
	action := flag.String("action", "on", "Power action: on, off, off-hard, reboot, reboot-hard (default: on)")

	flag.Parse()

	pass := os.Getenv("AMT_PASSWORD")
	if pass == "" {
		fmt.Fprintln(os.Stderr, "Error: AMT_PASSWORD environment variable is not set")
		os.Exit(1)
	}

	if *ip == "" {
		fmt.Println("Usage: AMT_PASSWORD=\"secret\" amt-power -ip <IP> [-action on|off|off-hard|reboot|reboot-hard] [-user admin] [-port 16992]")
		os.Exit(1)
	}

	act, ok := powerActions[strings.ToLower(*action)]
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: invalid action %q (valid: on, off, off-hard, reboot, reboot-hard)\n", *action)
		os.Exit(1)
	}

	if err := requestPowerState(*ip, *user, pass, *port, act); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
