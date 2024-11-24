package app

import (
	"net/http"
	"os"

	"github.com/andrew-hayworth22/sql-injection/app/common"
)

type Server struct {
	authenticator common.Authenticator
}

func NewServer(isSecure bool) Server {
	var auth common.Authenticator
	if isSecure {
		auth = SecureAuthenticator{}
		os.Setenv("STATUS", "SECURE")
	} else {
		auth = VulnerableAuthenticator{}
		os.Setenv("STATUS", "VULNERABLE")
	}

	return Server{
		authenticator: auth,
	}
}

func (s *Server) SwitchAuthenticator(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authenticator.(SecureAuthenticator); ok {
		s.authenticator = VulnerableAuthenticator{}
		os.Setenv("STATUS", "VULNERABLE")
	} else {
		s.authenticator = SecureAuthenticator{}
		os.Setenv("STATUS", "SECURE")
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	s.authenticator.Login(w, r)
}

func (s *Server) Register(w http.ResponseWriter, r *http.Request) {
	s.authenticator.Register(w, r)
}
