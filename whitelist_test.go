package traefik_ipwhitelist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewIPWhiteLister(t *testing.T) {
	testCases := []struct {
		desc          string
		whiteList     SkyloftWhiteList
		expectedError bool
	}{
		{
			desc: "invalid IP",
			whiteList: SkyloftWhiteList{
				SourceRange: []string{"foo"},
			},
			expectedError: true,
		},
		{
			desc: "valid IP",
			whiteList: SkyloftWhiteList{
				SourceRange: []string{"10.10.10.10"},
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
			whiteLister, err := New(context.Background(), next, &test.whiteList, "traefikTest")

			if test.expectedError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("expected no error but got one")
				}
				if whiteLister == nil {
					t.Errorf("expected whiteLister to be not nil but it was")
				}
			}
		})
	}
}

func TestIPWhiteLister_ServeHTTP(t *testing.T) {
	testCases := []struct {
		desc       string
		whiteList  SkyloftWhiteList
		remoteAddr string
		expected   int
	}{
		{
			desc: "authorized with remote address",
			whiteList: SkyloftWhiteList{
				SourceRange: []string{"20.20.20.20"},
			},
			remoteAddr: "20.20.20.20:1234",
			expected:   200,
		},
		{
			desc: "non authorized with remote address",
			whiteList: SkyloftWhiteList{
				SourceRange: []string{"20.20.20.20"},
			},
			remoteAddr: "20.20.20.21:1234",
			expected:   403,
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
			whiteLister, err := New(context.Background(), next, &test.whiteList, "traefikTest")
			if err != nil {
				t.Errorf("expected no error but got one")
			}

			recorder := httptest.NewRecorder()

			req := httptest.NewRequest(http.MethodGet, "http://10.10.10.10", nil)

			if len(test.remoteAddr) > 0 {
				req.RemoteAddr = test.remoteAddr
			}

			whiteLister.ServeHTTP(recorder, req)

			if test.expected != recorder.Code {
				t.Errorf("expected test.expected and recorder.Code to be equal but they weren't")
			}
		})
	}
}
