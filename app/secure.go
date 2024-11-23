package app

import (
	"net/http"

	"github.com/andrew-hayworth22/sql-injection/app/common"
)

// This authentication logic is protected against SQL injection attacks
type SecureAuthenticator struct{}

func (fa SecureAuthenticator) Login(w http.ResponseWriter, r *http.Request) {
	common.Success("Successfully logged in!", w, r)
}

func (fa SecureAuthenticator) Register(w http.ResponseWriter, r *http.Request) {
	common.Success("Successfully created an account!", w, r)
}
