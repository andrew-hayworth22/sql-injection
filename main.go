package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/a-h/templ"
	"github.com/andrew-hayworth22/sql-injection/app"
	"github.com/andrew-hayworth22/sql-injection/app/common"
	"github.com/andrew-hayworth22/sql-injection/templates"
	"github.com/lpernett/godotenv"
)

func main() {
	godotenv.Load()
	port := os.Getenv("PORT")
	dbName := os.Getenv("DB_NAME")

	err := common.ResetDatabase(dbName)
	if err != nil {
		fmt.Printf("error creating database: %v", err)
		return
	}

	registrationTemplate := templates.Registration()
	http.Handle("GET /", templ.Handler(registrationTemplate))

	loginTemplate := templates.Login()
	http.Handle("GET /login", templ.Handler(loginTemplate))

	http.HandleFunc("GET /status", common.Status)
	http.HandleFunc("GET /reset", common.Reset)

	fixed := flag.Bool("secure", false, "Pass this flag if you want security against SQL injection")
	flag.Parse()

	var authenticator common.Authenticator
	if *fixed {
		authenticator = app.SecureAuthenticator{}
		os.Setenv("STATUS", "SECURE")
	} else {
		authenticator = app.VulnerableAuthenticator{}
		os.Setenv("STATUS", "VULNERABLE")
	}

	http.HandleFunc("POST /register", authenticator.Register)
	http.HandleFunc("POST /login", authenticator.Login)

	fmt.Printf("Listening on %s\n", port)
	http.ListenAndServe(port, nil)
}
