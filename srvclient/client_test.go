package srvclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// GetToken used to take one pre-encoded base64 "creds" string interpolated
// after "Basic ". It now takes plain user/pass and lets net/http do the
// encoding, so this pins what actually goes on the wire.
func TestGetTokenSendsCorrectBasicHeader(t *testing.T) {
	var gotHeader, gotUser, gotPass string
	var parsed bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("Authorization")
		gotUser, gotPass, parsed = r.BasicAuth()
		w.Write([]byte(`{"Name":"n","Jwt":"tok"}`))
	}))
	defer srv.Close()

	tok, err := GetToken("apiacct", "s3cret:with:colons", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if tok == nil || *tok != "tok" {
		t.Fatalf("token = %v", tok)
	}
	if !parsed {
		t.Fatal("server could not parse the Basic header")
	}
	if gotUser != "apiacct" {
		t.Errorf("user = %q, want apiacct", gotUser)
	}
	// Only the first colon separates, so a password containing colons survives -
	// something hand-encoding got wrong easily.
	if gotPass != "s3cret:with:colons" {
		t.Errorf("pass = %q", gotPass)
	}
	if want := "Basic YXBpYWNjdDpzM2NyZXQ6d2l0aDpjb2xvbnM="; gotHeader != want {
		t.Errorf("header = %q, want %q", gotHeader, want)
	}
}

// A non-200 from the login endpoint must come back as an error, not a nil token
// the caller then dereferences - the nil-safety shape the rest of this package
// follows.
func TestGetTokenRejectsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer srv.Close()

	tok, err := GetToken("u", "wrong", srv.URL)
	if err == nil {
		t.Fatal("want an error for a 401")
	}
	if tok != nil {
		t.Errorf("token should be nil on failure, got %v", *tok)
	}
}

// An unreachable srvcman is the normal outcome of it living on another host, so
// it must return an error rather than panicking on a nil *http.Response.
func TestGetTokenUnreachableReturnsError(t *testing.T) {
	tok, err := GetToken("u", "p", "http://127.0.0.1:1/login")
	if err == nil {
		t.Fatal("want an error for an unreachable endpoint")
	}
	if tok != nil {
		t.Error("token should be nil")
	}
}
