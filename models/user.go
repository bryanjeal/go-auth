// Copyright 2017 Bryan Jeal <bryan@jeal.ca>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"encoding/gob"
	"net/mail"
	"strings"
	"time"

	"github.com/markbates/goth"
	uuid "github.com/satori/go.uuid"
)

// User Model holds account details and a slice of Providers
// Providers are a "linked" oAuth accounts (associated by email address)
type User struct {
	ID          uuid.UUID
	Email       string
	Password    string
	FirstName   string
	LastName    string
	IsActive    bool      `db:"is_active"`
	IsSuperuser bool      `db:"is_superuser"`
	IsDeleted   bool      `db:"is_deleted"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
	DeletedAt   time.Time `db:"deleted_at"`
	LoginAt     time.Time `db:"login_at"`
	AvatarURL   string    `db:"avatar_url"`
	Groups      []Group
	Permissions []Permission
	Providers   []goth.User
	newPassword bool
	rawPassword string
}

// Validate will check the User struct fields to ensure they are valid
func (u *User) Validate() error {
	// Check Email
	e, err := mail.ParseAddress(u.Email)
	if err != nil {
		return err
	}
	u.Email = e.Address

	// Check Password
	if u.newPassword {
		p := strings.TrimSpace(u.rawPassword)
		if len(p) == 0 {
			return ErrInvalidPassword
		}
	}

	// Check Names
	f := strings.TrimSpace(u.FirstName)
	u.FirstName = f
	l := strings.TrimSpace(u.LastName)
	u.LastName = l
	if len(u.FirstName) == 0 || len(u.LastName) == 0 {
		return ErrInvalidName
	}
	return nil
}

func init() {
	// need to gob.Register the User model for use within a session
	gob.Register(&User{})
}
