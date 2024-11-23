package common

import (
	"net/http"
)

type Authenticator interface {
	Register(http.ResponseWriter, *http.Request)
	Login(http.ResponseWriter, *http.Request)
}
