package common

import (
	"database/sql"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

func ConnectDatabase(dbName string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbName)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func ResetDatabase(dbName string) error {
	os.Remove(dbName)
	db, err := ConnectDatabase(dbName)
	if err != nil {
		return err
	}
	defer db.Close()

	createDbSql := `
		create table users(
			id integer primary key,
			username text,
			password text
		);

		insert into users(username, password) values
		('andy (vulnerable)', 'andy_pass'),
		('jeff (vulnerable)', 'jeff_pass'),
		(?, ?),
		(?, ?);

		create table data(
			id integer primary key,
			user_id integer,
			data text,
			constraint fk_users
			foreign key (user_id)
			references users(id)
		);

		insert into data (user_id, data) values
		(1, 'Sensitive information for Andy'),
		(1, 'This is important!'),
		(2, 'No one else should see this except Jeff!'),
		(2, 'For Jeff: do this'),
		(3, 'No one else should see this except Sally!'),
		(3, 'For Sally: do this'),
		(4, 'No one else should see this except Anna!'),
		(4, 'For Anna: do this');
	`

	transaction, err := db.Begin()
	if err != nil {
		return err
	}

	sallyName, _ := Encrypt("sally (secure)")
	annaName, _ := Encrypt("anna (secure)")

	sallyPass, _ := bcrypt.GenerateFromPassword([]byte("sally_pass"), bcrypt.DefaultCost)
	annaPass, _ := bcrypt.GenerateFromPassword([]byte("anna_pass"), bcrypt.DefaultCost)

	transaction.Exec(createDbSql, sallyName, sallyPass, annaName, annaPass)

	err = transaction.Commit()
	if err != nil {
		return err
	}

	return nil
}
