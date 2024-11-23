package app

import (
	"fmt"
	"net/http"
	"os"

	"github.com/andrew-hayworth22/sql-injection/app/common"
	"github.com/andrew-hayworth22/sql-injection/models"
)

// This authentication logic is vulnerable to SQL injection attacks
type VulnerableAuthenticator struct{}

func (ba VulnerableAuthenticator) Register(w http.ResponseWriter, r *http.Request) {
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

	createUserSQL := fmt.Sprintf(`insert into users(username, password) values ('%s', '%s');`, req.Username, encryptedPassword)

	transaction, err := db.Begin()
	if err != nil {
		transaction.Rollback()
		common.Fail("Failed starting transaction", w, r)
		return
	}

	_, err = transaction.Exec(createUserSQL)
	if err != nil {
		transaction.Rollback()
		common.Fail("Failed creating user", w, r)
		return
	}

	transaction.Commit()

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (ba VulnerableAuthenticator) Login(w http.ResponseWriter, r *http.Request) {
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

	getUserSQL := fmt.Sprintf(`select id, username, password from users where username = '%s' and password = '%s';`, req.Username, encryptedPassword)
	fmt.Println("Login Request - Get User SQL")
	fmt.Println(getUserSQL)

	db.Exec(getUserSQL)
	userRow := db.QueryRow(getUserSQL)

	var user models.User
	err = userRow.Scan(&user.Id, &user.Username, &user.EncryptedPassword)
	if err != nil {
		common.Fail("Invalid login credentials", w, r)
		return
	}

	var data []models.Data
	getDataSQL := fmt.Sprintf(`select id, user_id, data from data where data.user_id = %d`, user.Id)
	fmt.Println("Login Request - Get Data SQL")
	fmt.Println(getDataSQL)

	dataRow, err := db.Query(getDataSQL)
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
