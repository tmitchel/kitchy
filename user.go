package kitchy

import (
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

type User struct {
	ID       string
	Name     string
	Password string
}

func NewUser(name, password string, db *Database) (*User, error) {
	user := User{
		ID:       uuid.NewString(),
		Name:     name,
		Password: password,
	}

	err := user.Store(db)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (u User) Store(db *Database) error {
	sqlStatement := `
	INSERT INTO users (user_id, user_name, user_password)
	VALUES ($1, $2, $3)
	`
	_, err := db.Exec(sqlStatement, u.ID, u.Name, u.Password)
	if err != nil {
		return err
	}

	return nil
}

func GetUser(id string, db *Database) (*User, error) {
	var u User
	sqlStatement := `
	SELECT (user_id, user_name, user_password)
	FROM users
	WHERE user_id=$1
	`
	row := db.QueryRow(sqlStatement, id)
	switch err := row.Scan(&u.Name, &u.Password); err {
	case sql.ErrNoRows:
		return nil, fmt.Errorf("no rows for user id: %v", u.ID)
	case nil:
		return &u, nil
	default:
		return nil, err
	}
}

func GetUserByName(name string, db *Database) (*User, error) {
	var u User
	sqlStatement := `
	SELECT (user_id, user_name, user_password)
	FROM users
	WHERE user_name=$1
	`
	row := db.QueryRow(sqlStatement, name)
	switch err := row.Scan(&u.Name, &u.Password); err {
	case sql.ErrNoRows:
		return nil, fmt.Errorf("no rows for user id: %v", u.ID)
	case nil:
		return &u, nil
	default:
		return nil, err
	}
}

func GetUsers(db *Database) ([]*User, error) {
	var users []*User
	sqlStatement := `
	SELECT (user_id, user_name, user_password)
	FROM users;
	`
	rows, err := db.Query(sqlStatement)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var u User
		err = rows.Scan(&u.ID, &u.Name, &u.Password)
		if err != nil {
			return nil, err
		}
		users = append(users, &u)
	}

	if rows.Err() != nil {
		return nil, err
	}

	return users, nil
}
