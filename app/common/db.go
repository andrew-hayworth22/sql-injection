package common

import (
	"database/sql"
	"os"

	_ "github.com/mattn/go-sqlite3"
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
		('andy', 'meqLhfqh/U8='),
		('jeff', 'meqLhfqh/U8='),
		('sally', 'meqLhfqh/U8='),
		('jenny', 'meqLhfqh/U8='),
		('bre', 'meqLhfqh/U8=');

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
		(3, 'For Sally: this is sensitive'),
		(3, 'If anyone other than Sally sees this, then we need some new software!!'),
		(4, 'I really hope harmful attackers do not get this information.'),
		(4, 'What is goin on Jenny?'),
		(5, 'Bre!! This is for you'),
		(5, 'Pleeeease do not hack this pleeeease!!');
	`

	transaction, err := db.Begin()
	if err != nil {
		return err
	}

	transaction.Exec(createDbSql)

	err = transaction.Commit()
	if err != nil {
		return err
	}

	return nil
}
