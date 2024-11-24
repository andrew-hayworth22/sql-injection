package common

import (
	"net/http"
)

type FormRequest struct {
	Username string
	Password string
}

func GetRequest(w http.ResponseWriter, r *http.Request) (FormRequest, error) {
	r.ParseForm()
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	return FormRequest{
		Username: username,
		Password: password,
	}, nil
}
