package mocks

import (
	"time"

	"github.com/mfroeh/snippetbox/internal/models"
)

type UserModel struct{}

func (m *UserModel) Insert(name, email, password string) error {
	switch email {
	case "dupe@example.com":
		return models.ErrDuplicateEmail
	default:
		return nil
	}
}

func (m *UserModel) Authenticate(email, password string) (int, error) {
	if email == "alice@example.com" && password == "pa$$word" {
		return 1, nil
	}

	return 0, models.ErrInvalidCredentials
}

func (m *UserModel) Exists(id int) (bool, error) {
	switch id {
	case 1:
		return true, nil
	default:
		return false, nil
	}
}

func (m *UserModel) Get(id int) (models.User, error) {
	switch id {
	case 1:
		created, err := time.Parse(time.DateTime, "2022-01-01 09:18:24")
		if err != nil {
			panic(err)
		}
		return models.User{ID: 1, Email: "alice@example.com", Name: "Alice Jones", Created: created}, nil
	default:
		return models.User{}, models.ErrNoRecord
	}
}

func (m *UserModel) PasswordUpdate(id int, currentPassword, newPassword string) error {
	switch id {
	case 1:
		if currentPassword != "pa$$word" {
			return models.ErrInvalidCredentials
		}

		return nil
	default:
		return models.ErrNoRecord
	}
}
