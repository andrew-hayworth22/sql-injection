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

	db, err := common.ConnectDatabase(os.Getenv("DB_NAME"))
	if err != nil {
		common.Fail("Failed connecting to DB", w, r)
		return
	}

	createUserSQL := fmt.Sprintf(`insert into users(username, password) values ('%s', '%s') returning id;`, req.Username, req.Password)

	transaction, err := db.Begin()
	if err != nil {
		transaction.Rollback()
		common.Fail("Failed starting transaction", w, r)
		return
	}

	idRow := transaction.QueryRow(createUserSQL)
	if err != nil {
		transaction.Rollback()
		common.Fail("Failed creating user", w, r)
		return
	}
	var id int
	err = idRow.Scan(&id)
	if err != nil {
		transaction.Rollback()
		common.Fail("Failed creating user", w, r)
		return
	}

	createDataSQL := fmt.Sprintf(`insert into data (user_id, data) values (%d, 'Some data for you'), (%d, 'This is confidential!');`, id, id)
	_, err = transaction.Exec(createDataSQL)
	if err != nil {
		transaction.Rollback()
		common.Fail("Failed generating data: "+err.Error(), w, r)
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

	getUserSQL := fmt.Sprintf(`select id, username, password from users where username = '%s' and password = '%s';`, req.Username, req.Password)
	fmt.Println("Login Request - Get User SQL")
	fmt.Println(getUserSQL)

	db.Exec(getUserSQL)
	userRow := db.QueryRow(getUserSQL)

	var user models.User
	err = userRow.Scan(&user.Id, &user.Username, &user.Password)
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
