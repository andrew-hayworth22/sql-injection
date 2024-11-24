package app

import (
	"net/http"
	"os"

	"github.com/andrew-hayworth22/sql-injection/app/common"
	"github.com/andrew-hayworth22/sql-injection/models"
)

// This authentication logic is protected against SQL injection attacks
type SecureAuthenticator struct{}

func (fa SecureAuthenticator) Register(w http.ResponseWriter, r *http.Request) {
	req, err := common.GetRequest(w, r)
	if err != nil {
		return
	}

	if len(req.Password) < 6 {
		common.Fail("Password is too short(must be greater than or equal to 6 characters)", w, r)
		return
	}

	encryptedPassword, err := common.Encrypt(req.Password)
	if err != nil {
		common.Fail("Failed encrypting password", w, r)
		return
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

	_, err = createUserStmt.Exec(req.Username, encryptedPassword)
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

	db, err := common.ConnectDatabase(os.Getenv("DB_NAME"))
	if err != nil {
		common.Fail("Failed connecting to DB", w, r)
		return
	}
	defer db.Close()

	encryptedPassword, err := common.Encrypt(req.Password)
	if err != nil {
		common.Fail("Critical error: failed encryption", w, r)
		return
	}

	getUserSQL := "select id, username, password from users where username = ? and password = ?;"
	getUserStmt, err := db.Prepare(getUserSQL)
	if err != nil {
		common.Fail("Failed login", w, r)
		return
	}

	userRow := getUserStmt.QueryRow(req.Username, encryptedPassword)

	var user models.User
	err = userRow.Scan(&user.Id, &user.Username, &user.EncryptedPassword)
	if err != nil {
		common.Fail("Invalid login credentials", w, r)
		return
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
