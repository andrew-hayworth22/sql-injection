package models

type User struct {
	Id                int    `db:"id"`
	Username          string `db:"username"`
	EncryptedPassword string `db:"password"`
}

type Data struct {
	Id     int    `db:"id"`
	UserId int    `db:"user_id"`
	Data   string `db:"data"`
}
