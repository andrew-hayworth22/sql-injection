package app

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/andrew-hayworth22/sql-injection/app/common"
	"github.com/andrew-hayworth22/sql-injection/models"
	"golang.org/x/crypto/bcrypt"
)

// This authentication logic is protected against SQL injection attacks
// Features not included in vulnerable implementation:
//   - Password Hashing
//   - Username Encryption
//   - Prepared SQL Statements

type SecureAuthenticator struct{}

func (fa SecureAuthenticator) Register(w http.ResponseWriter, r *http.Request) {
	req, err := common.GetRequest(w, r)
	if err != nil {
		return
	}

	sanitizedReq, err := SanitizeRequest(req)
	if err != nil {
		common.Fail("Validation error: "+err.Error(), w, r)
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(sanitizedReq.Password), bcrypt.DefaultCost)
	if err != nil {
		common.Fail("Failed hashing password", w, r)
		return
	}

	encryptedUsername, err := common.Encrypt(req.Username)
	if err != nil {
		common.Fail("Failed encrypting data", w, r)
	}

	db, err := common.ConnectDatabase(os.Getenv("DB_NAME"))
	if err != nil {
		common.Fail("Failed connecting to DB", w, r)
		return
	}

	transaction, err := db.Begin()
	if err != nil {
		transaction.Rollback()
		common.Fail("Failed starting transaction", w, r)
		return
	}

	createUserSQL := "insert into users(username, password) values (?, ?);"
	createUserStmt, err := db.Prepare(createUserSQL)
	if err != nil {
		common.Fail("Failed creating user", w, r)
		return
	}

	_, err = createUserStmt.Exec(encryptedUsername, passwordHash)
	if err != nil {
		transaction.Rollback()
		common.Fail("Failed creating user", w, r)
		return
	}

	transaction.Commit()

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (fa SecureAuthenticator) Login(w http.ResponseWriter, r *http.Request) {
	req, err := common.GetRequest(w, r)
	if err != nil {
		return
	}

	sanitizedReq, err := SanitizeRequest(req)
	if err != nil {
		common.Fail("Validation error: "+err.Error(), w, r)
		return
	}

	encryptedUsername, err := common.Encrypt(sanitizedReq.Username)
	if err != nil {
		common.Fail("Failed encrypting data", w, r)
		return
	}

	db, err := common.ConnectDatabase(os.Getenv("DB_NAME"))
	if err != nil {
		common.Fail("Failed connecting to DB", w, r)
		return
	}
	defer db.Close()

	getUserSQL := "select id, username, password from users where username = ?"
	getUserStmt, err := db.Prepare(getUserSQL)
	if err != nil {
		common.Fail("Failed login", w, r)
		return
	}

	userRow := getUserStmt.QueryRow(encryptedUsername)

	var user models.User
	err = userRow.Scan(&user.Id, &user.Username, &user.Password)
	if err != nil {
		common.Fail("Invalid login credentials", w, r)
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		common.Fail("Invalid login credentials", w, r)
		return
	}

	user.Username, err = common.Decrypt(user.Username)
	if err != nil {
		common.Fail("Failed decrypting username", w, r)
	}

	var data []models.Data
	getDataSQL := "select id, user_id, data from data where data.user_id = ?"
	getDataStmt, err := db.Prepare(getDataSQL)
	if err != nil {
		common.Fail("Failed retrieving data", w, r)
		return
	}

	dataRow, err := getDataStmt.Query(user.Id)
	if err != nil {
		common.Fail("Failed login", w, r)
		return
	}
	defer dataRow.Close()
	for dataRow.Next() {
		d := models.Data{}
		err := dataRow.Scan(&d.Id, &d.UserId, &d.Data)
		if err != nil {
			common.Fail("Failed retrieving data: ", w, r)
			return
		}
		data = append(data, d)
	}

	common.Home(user.Username, data, w, r)
}

func SanitizeRequest(req common.FormRequest) (common.FormRequest, error) {
	username := strings.TrimSpace(req.Username)
	if len(username) == 0 {
		return common.FormRequest{}, errors.New("no username provided")
	}

	if len(req.Password) == 0 {
		return common.FormRequest{}, errors.New("no password provided")
	}
	if len(req.Password) < 8 {
		return common.FormRequest{}, errors.New("password is too short (must be 8 characters or more)")
	}

	return common.FormRequest{
		Username: username,
		Password: req.Password,
	}, nil
}
