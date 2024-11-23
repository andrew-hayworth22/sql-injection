package common

import (
	"errors"
	"net/http"
	"strings"
)

type FormRequest struct {
	Username string
	Password string
}

func GetRequest(w http.ResponseWriter, r *http.Request) (FormRequest, error) {
	r.ParseForm()
	username := r.Form.Get("username")
	trimmedUsername := strings.TrimSpace(username)
	if len(trimmedUsername) == 0 {
		Fail("No username provided", w, r)
		return FormRequest{}, errors.New("no username provided")
	}

	password := r.Form.Get("password")
	trimmedPassword := strings.TrimSpace(password)
	if len(trimmedPassword) == 0 {
		Fail("No password provided", w, r)
		return FormRequest{}, errors.New("no password provided")
	}

	return FormRequest{
		Username: trimmedUsername,
		Password: trimmedPassword,
	}, nil
}
