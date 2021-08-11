package kitchy

import (
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

type Pantry struct {
	ID        string
	Name      string
	CreatedBy string
}

func NewPantry(name, creator string, db *Database) (*Pantry, error) {
	pantry := Pantry{
		ID:        uuid.NewString(),
		Name:      name,
		CreatedBy: creator,
	}

	err := pantry.Store(db)
	if err != nil {
		return nil, err
	}

	return &pantry, nil
}

func (p Pantry) Store(db *Database) error {
	sqlStatement := `
	INSERT INTO pantries (pantry_id, pantry_name)
	VALUES ($1, $2)
	`
	_, err := db.Exec(sqlStatement, p.ID, p.Name)
	if err != nil {
		return err
	}

	return nil
}

func GetPantry(id string, db *Database) (*Pantry, error) {
	var p Pantry
	sqlStatement := `
	SELECT (pantry_id, pantry_name)
	FROM pantries
	WHERE pantry_id=$1
	`
	row := db.QueryRow(sqlStatement, id)
	switch err := row.Scan(&p.Name); err {
	case sql.ErrNoRows:
		return nil, fmt.Errorf("no rows for pantry id: %v", p.ID)
	case nil:
		return &p, nil
	default:
		return nil, err
	}
}

func GetPantryByName(name string, db *Database) (*Pantry, error) {
	var p Pantry
	sqlStatement := `
	SELECT (pantry_id, pantry_name)
	FROM pantries
	WHERE pantry_name=$1
	`
	row := db.QueryRow(sqlStatement, name)
	switch err := row.Scan(&p.Name); err {
	case sql.ErrNoRows:
		return nil, fmt.Errorf("no rows for pantry id: %v", p.ID)
	case nil:
		return &p, nil
	default:
		return nil, err
	}
}

func GetPantries(db *Database) ([]*Pantry, error) {
	var pantries []*Pantry
	sqlStatement := `
	SELECT (pantry_id, pantry_name)
	FROM pantries;
	`
	rows, err := db.Query(sqlStatement)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var p Pantry
		err = rows.Scan(&p.ID, &p.Name)
		if err != nil {
			return nil, err
		}
		pantries = append(pantries, &p)
	}

	if rows.Err() != nil {
		return nil, err
	}

	return pantries, nil
}
