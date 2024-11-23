package common

import (
	"net/http"
	"os"

	"github.com/andrew-hayworth22/sql-injection/models"
	"github.com/andrew-hayworth22/sql-injection/templates"
)

func Success(body string, w http.ResponseWriter, r *http.Request) {
	templates.Result("Success", body).Render(r.Context(), w)
}

func Fail(body string, w http.ResponseWriter, r *http.Request) {
	templates.Result("Failure", body).Render(r.Context(), w)
}

func Home(username string, data []models.Data, w http.ResponseWriter, r *http.Request) {
	dataStrings := []string{}
	for _, d := range data {
		dataStrings = append(dataStrings, d.Data)
	}
	templates.Home(username, data).Render(r.Context(), w)
}

func Status(w http.ResponseWriter, r *http.Request) {
	db, err := ConnectDatabase(os.Getenv("DB_NAME"))
	if err != nil {
		Fail("Failed connecting to DB", w, r)
		return
	}

	var users []models.User
	getUsersSQL := `select id, username, password from users;`

	userRow, err := db.Query(getUsersSQL)
	if err != nil {
		Fail("Failed retrieving users", w, r)
		return
	}
	defer userRow.Close()
	for userRow.Next() {
		user := models.User{}
		err := userRow.Scan(&user.Id, &user.Username, &user.EncryptedPassword)
		if err != nil {
			Fail("Failed retrieving users: ", w, r)
			return
		}
		users = append(users, user)
	}

	var datas []models.Data
	getDataSQL := `select id, user_id, data from data;`

	dataRow, err := db.Query(getDataSQL)
	if err != nil {
		Fail("Failed retrieving data", w, r)
		return
	}
	defer dataRow.Close()
	for dataRow.Next() {
		data := models.Data{}
		err := dataRow.Scan(&data.Id, &data.UserId, &data.Data)
		if err != nil {
			Fail("Failed retrieving data", w, r)
			return
		}
		datas = append(datas, data)
	}

	templates.Status(users, datas).Render(r.Context(), w)
}

func Reset(w http.ResponseWriter, r *http.Request) {
	ResetDatabase(os.Getenv("DB_NAME"))

	http.Redirect(w, r, "/status", http.StatusSeeOther)
}
