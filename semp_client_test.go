package solacevaultplugin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSEMPClient_ChangePassword_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify basic auth
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "adminpass" {
			t.Errorf("bad auth: user=%q pass=%q ok=%v", user, pass, ok)
		}

		// Verify POST to /SEMP
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/SEMP" {
			t.Errorf("path = %q, want /SEMP", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<rpc-reply>
			<execute-result code="ok"/>
		</rpc-reply>`))
	}))
	defer server.Close()

	client := &SEMPClient{
		SEMPURL:       server.URL,
		AdminUsername: "admin",
		AdminPassword: "adminpass",
		SEMPVersion:   "soltr/10_4",
		HTTPClient:    server.Client(),
	}

	err := client.ChangePassword("testuser", "newpassword")
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
}

func TestSEMPClient_ChangePassword_SEMPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<rpc-reply>
			<execute-result code="fail"/>
			<parse-error>Invalid username</parse-error>
		</rpc-reply>`))
	}))
	defer server.Close()

	client := &SEMPClient{
		SEMPURL:       server.URL,
		AdminUsername: "admin",
		AdminPassword: "adminpass",
		HTTPClient:    server.Client(),
	}

	err := client.ChangePassword("testuser", "newpassword")
	if err == nil {
		t.Fatal("expected error for SEMP failure")
	}
}

func TestSEMPClient_ChangePassword_HTTPError(t *testing.T) {
	client := &SEMPClient{
		SEMPURL:       "http://127.0.0.1:1",
		AdminUsername: "admin",
		AdminPassword: "adminpass",
		HTTPClient:    http.DefaultClient,
	}

	err := client.ChangePassword("testuser", "newpassword")
	if err == nil {
		t.Fatal("expected error for unreachable broker")
	}
}

func TestBuildChangePasswordXML(t *testing.T) {
	xml := buildChangePasswordXML("soltr/10_4", "myuser", "mypass")
	expected := `<rpc semp-version="soltr/10_4"><username><name>myuser</name><change-password><password>mypass</password></change-password></username></rpc>`
	if xml != expected {
		t.Errorf("got:\n%s\nwant:\n%s", xml, expected)
	}
}

func TestBuildChangePasswordXML_NoVersion(t *testing.T) {
	xml := buildChangePasswordXML("", "myuser", "mypass")
	expected := `<rpc><username><name>myuser</name><change-password><password>mypass</password></change-password></username></rpc>`
	if xml != expected {
		t.Errorf("got:\n%s\nwant:\n%s", xml, expected)
	}
}
