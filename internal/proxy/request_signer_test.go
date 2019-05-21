package proxy

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

// Convenience variables and utilities.
var urlExample = "https://foo.sso.example.com/path"

func addHeaders(req *http.Request, examples []string, extras map[string][]string) {
	var signedHeaderExamples = map[string][]string{
		"Content-Length":     {"1234"},
		"Content-Md5":        {"F00D"},
		"Content-Type":       {"application/json"},
		"Date":               {"2018-11-08"},
		"Authorization":      {"Bearer ab12cd34"},
		"Cookie":             {""},
		"X-Forwarded-User":   {"octoboi"},
		"X-Forwarded-Email":  {"octoboi@example.com"},
		"X-Forwarded-Groups": {"molluscs", "security_applications"},
	}

	for _, signedHdr := range examples {
		for _, value := range signedHeaderExamples[signedHdr] {
			req.Header.Add(signedHdr, value)
		}
	}
	for extraHdr, values := range extras {
		for _, value := range values {
			req.Header.Add(extraHdr, value)
		}
	}
}

func TestRepr_UrlRepresentation(t *testing.T) {
	testURL := func(url string, expect string) {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Errorf("could not build request: %s", err)
		}

		repr, err := mapRequestToHashInput(req)
		if err != nil {
			t.Errorf("could not map request to hash input: %s", err)
		}
		testutil.Equal(t, expect, repr)
	}

	testURL("http://foo.sso.example.com/path/to/resource", "/path/to/resource")
	testURL("http://foo.sso.example.com/path?", "/path")
	testURL("http://foo.sso.example.com/path/to?query#fragment", "/path/to?query#fragment")
	testURL("https://foo.sso.example.com:4321/path#fragment", "/path#fragment")
	testURL("http://foo.sso.example.com/path?query&param=value#", "/path?query&param=value")
}

func TestRepr_HeaderRepresentation(t *testing.T) {
	testHeaders := func(include []string, extra map[string][]string, expect string) {
		req, err := http.NewRequest("GET", urlExample, nil)
		if err != nil {
			t.Errorf("could not build request: %s", err)
		}
		addHeaders(req, include, extra)
		repr, err := mapRequestToHashInput(req)
		if err != nil {
			t.Errorf("could not map request to hash input: %s", err)
		}
		testutil.Equal(t, expect, repr)
	}

	// Partial set of signed headers.
	testHeaders([]string{"Authorization", "X-Forwarded-Groups"}, nil,
		"Bearer ab12cd34\n"+
			"molluscs,security_applications\n"+
			"/path")

	// Full set of signed headers.
	testHeaders(signedHeaders, nil,
		"1234\n"+
			"F00D\n"+
			"application/json\n"+
			"2018-11-08\n"+
			"Bearer ab12cd34\n"+
			"octoboi\n"+
			"octoboi@example.com\n"+
			"molluscs,security_applications\n"+
			"/path")

	// Partial set of signed headers, plus another header (should not appear in representation).
	testHeaders([]string{"Authorization", "X-Forwarded-Email"},
		map[string][]string{"X-Octopus-Stuff": {"54321"}},
		"Bearer ab12cd34\n"+
			"octoboi@example.com\n"+
			"/path")

	// Only unsigned headers.
	testHeaders(nil, map[string][]string{"X-Octopus-Stuff": {"83721"}}, "/path")
}

func TestRepr_PostWithBody(t *testing.T) {
	req, err := http.NewRequest("POST", urlExample, strings.NewReader("something\nor other"))
	if err != nil {
		t.Errorf("could not build request: %s", err)
	}
	addHeaders(req, []string{"X-Forwarded-Email", "X-Forwarded-Groups"},
		map[string][]string{"X-Octopus-Stuff": {"54321"}})

	repr, err := mapRequestToHashInput(req)
	if err != nil {
		t.Errorf("could not map request to hash input: %s", err)
	}
	testutil.Equal(t,
		"octoboi@example.com\n"+
			"molluscs,security_applications\n"+
			"/path\n"+
			"something\n"+
			"or other",
		repr)
}

func TestSignatureRoundTripDecoding(t *testing.T) {
	// Keys used for signing/validating request.
	privateKey, err := ioutil.ReadFile("testdata/private_key.pem")
	testutil.Assert(t, err == nil, "error reading private key from testdata")

	publicKey, err := ioutil.ReadFile("testdata/public_key.pub")
	testutil.Assert(t, err == nil, "error reading public key from testdata")

	// Build the RequestSigner object used to generate the request signature header.
	requestSigner, err := NewRequestSigner(string(privateKey))
	testutil.Assert(t, err == nil, "could not initialize request signer: %s", err)

	// And build the rsa.PublicKey object that will help verify the signature.
	verifierKey, err := func() (*rsa.PublicKey, error) {
		if block, _ := pem.Decode(publicKey); block == nil {
			return nil, fmt.Errorf("could not read PEM block from public key")
		} else if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("could not read key from public key bytes: %s", err)
		} else {
			return key, nil
		}
	}()
	testutil.Assert(t, err == nil, "could not construct public key: %s", err)

	// Build the Request to be signed.
	req, err := http.NewRequest("POST", urlExample, strings.NewReader("something\nor other"))
	testutil.Assert(t, err == nil, "could not construct request: %s", err)
	addHeaders(req, []string{"X-Forwarded-Email", "X-Forwarded-Groups"},
		map[string][]string{"X-Octopus-Stuff": {"54321"}})

	// Sign the request, and extract its signature from the header.
	err = requestSigner.Sign(req)
	testutil.Assert(t, err == nil, "could not sign request: %s", err)
	sig, _ := base64.URLEncoding.DecodeString(req.Header.Get("Sso-Signature"))

	// Hardcoded expected hash, computed from the request.
	expectedHash, _ := hex.DecodeString(
		"04158c00fbecccd8b5dca58634a0a7f28bf5ad908f19cb1b404bdd37bb4485a9")
	err = rsa.VerifyPKCS1v15(verifierKey, crypto.SHA256, expectedHash, sig)
	testutil.Assert(t, err == nil, "could not verify request signature: %s", err)

	// Verify that the signing-key header is the hash of the public-key.
	var pubKeyHash []byte
	hasher := sha256.New()
	_, _ = hasher.Write(publicKey)
	pubKeyHash = hasher.Sum(pubKeyHash)
	testutil.Equal(t, hex.EncodeToString(pubKeyHash), req.Header.Get("kid"))
}

func genRequestSignerVerifier(t *testing.T) (*RequestSigner, *RequestVerifier) {
	privateKey, err := ioutil.ReadFile("testdata/private_key.pem")
	if err != nil {
		t.Fatalf("could not read private key from testdata: %v", err)
	}

	// Build the RequestSigner object used to generate the request signature header.
	requestSigner, err := NewRequestSigner(string(privateKey))
	if err != nil {
		t.Fatalf("could not create request signer: %v", err)
	}

	publicKey, err := ioutil.ReadFile("testdata/public_key.pub")
	if err != nil {
		t.Fatalf("could not public key form testdata: %v", err)
	}

	requestVerifier, err := NewRequestVerifier(publicKey)
	if err != nil {
		t.Fatalf("could not create request verifier: %v", err)
	}

	return requestSigner, requestVerifier
}

func TestRequestBodySignatures(t *testing.T) {
	// this is particularly problematic utf8 string
	badUTFBytes, err := hex.DecodeString("efbfbeefbfbfedafbfedbfbf")
	if err != nil {
		t.Fatalf("unexpected error decoding hex string: %v", err)
	}

	testCases := map[string]struct {
		Method  string
		Headers http.Header
		Body    io.Reader
	}{
		"get nil request body": {
			Method: "GET",
			Headers: map[string][]string{
				"X-Forwarded-User":   []string{"any.user"},
				"X-Forwarded-Email":  []string{"any.user@domain.com"},
				"X-Forwarded-Groups": []string{"org1", "div1"},
			},
			Body: nil,
		},
		"post with string request body": {
			Method: "POST",
			Headers: map[string][]string{
				"X-Forwarded-User":   []string{"any.user"},
				"X-Forwarded-Email":  []string{"any.user@domain.com"},
				"X-Forwarded-Groups": []string{"org1", "div1"},
			},
			Body: strings.NewReader("something or\nother"),
		},
		"post with emoji body": {
			Method: "POST",
			Headers: map[string][]string{
				"X-Forwarded-User":   []string{"any.user"},
				"X-Forwarded-Email":  []string{"any.user@domain.com"},
				"X-Forwarded-Groups": []string{"org1", "div1"},
			},
			Body: bytes.NewBuffer([]byte("😅")),
		},
		"post with non-utf 8 string": {
			Method: "POST",
			Headers: map[string][]string{
				"X-Forwarded-User":   []string{"any.user"},
				"X-Forwarded-Email":  []string{"any.user@domain.com"},
				"X-Forwarded-Groups": []string{"org1", "div1"},
			},
			Body: bytes.NewBuffer(badUTFBytes),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			signer, verifier := genRequestSignerVerifier(t)

			backend := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// verify the request on the server
				err := verifier.Verify(req)
				if err != nil {
					t.Fatalf("unexpected error verifying signature: %v", err)
				}
				rw.WriteHeader(http.StatusOK)
			}))
			defer backend.Close()
			backendURL, err := url.Parse(backend.URL)
			if err != nil {
				t.Fatalf("unexpected error parsing backend url: %v", err)
			}

			frontend := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				for key, vals := range tc.Headers {
					for _, val := range vals {
						req.Header.Add(key, val)
					}
				}

				err := signer.Sign(req)
				if err != nil {
					t.Fatalf("unexpected error signing request: %v", err)
				}

				reverseProxy := httputil.NewSingleHostReverseProxy(backendURL)
				reverseProxy.ServeHTTP(rw, req)
			}))
			defer frontend.Close()

			// build the request to be signed.
			req, err := http.NewRequest(tc.Method, frontend.URL, tc.Body)
			if err != nil {
				t.Fatalf("could not construct http request: %v", err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("got unexpected error doing http request: %v", err)
			}

			if resp.StatusCode != http.StatusOK {
				t.Logf("have: %v", resp.StatusCode)
				t.Logf("want: %v", http.StatusOK)
				t.Fatalf("got unexpected status code")
			}
		})
	}
}

func TestRequestBodySignaturesFromDirector(t *testing.T) {
	// this is particularly problematic utf8 string
	badUTFBytes, err := hex.DecodeString("efbfbeefbfbfedafbfedbfbf")
	if err != nil {
		t.Fatalf("unexpected error decoding hex string: %v", err)
	}

	testCases := map[string]struct {
		Method  string
		Headers http.Header
		Body    io.Reader
	}{
		"get nil request body": {
			Method: "GET",
			Headers: map[string][]string{
				"X-Forwarded-User":   []string{"any.user"},
				"X-Forwarded-Email":  []string{"any.user@domain.com"},
				"X-Forwarded-Groups": []string{"org1", "div1"},
			},
			Body: nil,
		},
		"post with string request body": {
			Method: "POST",
			Headers: map[string][]string{
				"X-Forwarded-User":   []string{"any.user"},
				"X-Forwarded-Email":  []string{"any.user@domain.com"},
				"X-Forwarded-Groups": []string{"org1", "div1"},
			},
			Body: strings.NewReader("something or\nother"),
		},
		"post with emoji body": {
			Method: "POST",
			Headers: map[string][]string{
				"X-Forwarded-User":   []string{"any.user"},
				"X-Forwarded-Email":  []string{"any.user@domain.com"},
				"X-Forwarded-Groups": []string{"org1", "div1"},
			},
			Body: bytes.NewBuffer([]byte("😅")),
		},
		"post with non-utf 8 string": {
			Method: "POST",
			Headers: map[string][]string{
				"X-Forwarded-User":   []string{"any.user"},
				"X-Forwarded-Email":  []string{"any.user@domain.com"},
				"X-Forwarded-Groups": []string{"org1", "div1"},
			},
			Body: bytes.NewBuffer(badUTFBytes),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			signer, verifier := genRequestSignerVerifier(t)

			backend := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// verify the request on the server
				err := verifier.Verify(req)
				if err != nil {
					t.Fatalf("unexpected error verifying signature: %v", err)
				}
				rw.WriteHeader(http.StatusOK)
			}))
			defer backend.Close()
			backendURL, err := url.Parse(backend.URL)
			if err != nil {
				t.Fatalf("unexpected error parsing backend url: %v", err)
			}

			frontend := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				for key, vals := range tc.Headers {
					for _, val := range vals {
						req.Header.Add(key, val)
					}
				}

				reverseProxy := httputil.NewSingleHostReverseProxy(backendURL)

				// save pointer to old director
				director := reverseProxy.Director
				reverseProxy.Director = func(r *http.Request) {
					// call older director
					director(r)

					// sign request
					err := signer.Sign(r)
					if err != nil {
						t.Fatalf("unexpected error signing request: %v", err)
					}
				}

				// proxy request
				reverseProxy.ServeHTTP(rw, req)
			}))
			defer frontend.Close()

			// build the request to be signed.
			req, err := http.NewRequest(tc.Method, frontend.URL, tc.Body)
			if err != nil {
				t.Fatalf("could not construct http request: %v", err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("got unexpected error doing http request: %v", err)
			}

			if resp.StatusCode != http.StatusOK {
				t.Logf("have: %v", resp.StatusCode)
				t.Logf("want: %v", http.StatusOK)
				t.Fatalf("got unexpected status code")
			}
		})
	}
}
