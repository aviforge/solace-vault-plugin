package solacevaultplugin

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SEMPClient communicates with a Solace broker via SEMP v1 XML.
type SEMPClient struct {
	SEMPURL       string
	AdminUsername string
	AdminPassword string
	SEMPVersion   string
	TLSSkipVerify bool
	HTTPClient    *http.Client
}

type sempReply struct {
	XMLName       xml.Name          `xml:"rpc-reply"`
	ExecuteResult sempExecuteResult `xml:"execute-result"`
	ParseError    string            `xml:"parse-error"`
}

type sempExecuteResult struct {
	Code string `xml:"code,attr"`
}

// NewSEMPClient creates a client from a BrokerConfig.
func NewSEMPClient(config *BrokerConfig) *SEMPClient {
	transport := &http.Transport{
		DisableKeepAlives: true,
	}
	if config.TLSSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	httpClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &SEMPClient{
		SEMPURL:       config.SEMPURL,
		AdminUsername: config.AdminUsername,
		AdminPassword: config.AdminPassword,
		SEMPVersion:   config.SEMPVersion,
		TLSSkipVerify: config.TLSSkipVerify,
		HTTPClient:    httpClient,
	}
}

// ChangePassword changes a CLI user's password on the broker via SEMP v1.
func (c *SEMPClient) ChangePassword(ctx context.Context, cliUsername, newPassword string) error {
	body := buildChangePasswordXML(c.SEMPVersion, cliUsername, newPassword)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.SEMPURL+"/SEMP", strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/xml")
	req.SetBasicAuth(c.AdminUsername, c.AdminPassword)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("SEMP request to %s failed: %w", c.SEMPURL, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("reading SEMP response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SEMP returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var reply sempReply
	if err := xml.Unmarshal(respBody, &reply); err != nil {
		return fmt.Errorf("parsing SEMP response: %w", err)
	}

	if reply.ExecuteResult.Code != "ok" {
		errMsg := reply.ParseError
		if errMsg == "" {
			errMsg = fmt.Sprintf("execute-result code=%q", reply.ExecuteResult.Code)
		}
		return fmt.Errorf("SEMP command failed: %s", errMsg)
	}

	return nil
}

func escapeXML(s string) string {
	var buf strings.Builder
	xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

func buildChangePasswordXML(sempVersion, username, password string) string {
	var b strings.Builder
	if sempVersion != "" {
		fmt.Fprintf(&b, `<rpc semp-version="%s">`, escapeXML(sempVersion))
	} else {
		b.WriteString(`<rpc>`)
	}
	fmt.Fprintf(&b, `<username><name>%s</name><change-password><password>%s</password></change-password></username>`, escapeXML(username), escapeXML(password))
	b.WriteString(`</rpc>`)
	return b.String()
}
