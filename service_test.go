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
	"os"
	"strings"
	"testing"

	"github.com/bryanjeal/go-nonce"
	tmpl "github.com/bryanjeal/go-tmpl"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/satori/go.uuid"
	mailgun "gopkg.in/mailgun/mailgun-go.v1"
)

const sqlCreateUserTable string = `
PRAGMA foreign_keys = OFF;

-- Schema: auth
ATTACH "auth.sdb" AS "auth";
BEGIN;
CREATE TABLE "auth"."group"(
  "id" BINARY(16) PRIMARY KEY NOT NULL,
  "name" VARCHAR(255) NOT NULL,
  "slug" VARCHAR(255) NOT NULL,
  CONSTRAINT "name_UNIQUE"
    UNIQUE("name"),
  CONSTRAINT "slug_UNIQUE"
    UNIQUE("slug")
);
CREATE TABLE "auth"."permission"(
  "id" BINARY(16) PRIMARY KEY NOT NULL,
  "name" VARCHAR(255) NOT NULL,
  "slug" VARCHAR(255) NOT NULL,
  "object" VARCHAR(255),
  CONSTRAINT "name_UNIQUE"
    UNIQUE("name"),
  CONSTRAINT "slug_UNIQUE"
    UNIQUE("slug")
);
CREATE INDEX "auth"."permission.idx_object" ON "permission" ("object");
CREATE INDEX "auth"."permission.idx_slug" ON "permission" ("slug");
CREATE TABLE "auth"."group_permission"(
  "id_group" BINARY(16) NOT NULL,
  "id_permission" BINARY(16) NOT NULL,
  CONSTRAINT "fk_group"
    FOREIGN KEY("id_group")
    REFERENCES "group"("id"),
  CONSTRAINT "fk_permission"
    FOREIGN KEY("id_permission")
    REFERENCES "permission"("id")
);
CREATE INDEX "auth"."group_permission.idx_group" ON "group_permission" ("id_group");
CREATE INDEX "auth"."group_permission.idx_permission" ON "group_permission" ("id_permission");
CREATE TABLE "auth"."user"(
  "id" BINARY(16) PRIMARY KEY NOT NULL,
  "email" VARCHAR(255) NOT NULL,
  "password" VARCHAR(255) NOT NULL,
  "firstname" VARCHAR(45) NOT NULL,
  "lastname" VARCHAR(45) NOT NULL,
  "is_superuser" BOOL NOT NULL DEFAULT 0,
  "is_active" BOOL NOT NULL DEFAULT 0,
  "is_deleted" BOOL NOT NULL DEFAULT 0,
  "created_at" DATETIME NOT NULL,
  "updated_at" DATETIME NOT NULL,
  "deleted_at" DATETIME NOT NULL,
  "login_at" DATETIME NOT NULL,
  "avatar_url" VARCHAR(45),
  CONSTRAINT "email_UNIQUE"
    UNIQUE("email")
);
CREATE TABLE "auth"."user_group"(
  "id_user" BINARY(16) NOT NULL,
  "id_group" BINARY(16) NOT NULL,
  CONSTRAINT "fk_user"
    FOREIGN KEY("id_user")
    REFERENCES "user"("id"),
  CONSTRAINT "fk_group"
    FOREIGN KEY("id_group")
    REFERENCES "group"("id")
);
CREATE INDEX "auth"."user_group.idx_user" ON "user_group" ("id_user");
CREATE INDEX "auth"."user_group.idx_group" ON "user_group" ("id_group");
CREATE TABLE "auth"."user_permission"(
  "id_user" BINARY(16) NOT NULL,
  "id_permission" BINARY(16) NOT NULL,
  CONSTRAINT "fk_user"
    FOREIGN KEY("id_user")
    REFERENCES "user"("id"),
  CONSTRAINT "fk_permission"
    FOREIGN KEY("id_permission")
    REFERENCES "permission"("id")
);
CREATE INDEX "auth"."user_permission.idx_user" ON "user_permission" ("id_user");
CREATE INDEX "auth"."user_permission.idx_permission" ON "user_permission" ("id_permission");
COMMIT;
`

// tUser is the base test user
var tUser User

// Service that all tests will use
var auth Service

// ENV variables
var (
	DOMAIN       string
	APIKEY       string
	PUBLICAPIKEY string
	EMAILTO      string
)

// To run TestService successfully you will need to include the following ENV variables:
// MGDOMAIN: Mailgun Account DOMAIN
// MGAPIKEY: Mailgun Account Secret/Private API Key
// MGPUBLICAPIKEY: Mailgun Account Public API Key
// TOEMAIL: Email account to verify the test emails are working
//
// Example Command: env MGDOMAIN=sandboxXXXX.mailgun.org MGAPIKEY=key-XXXX MGPUBLICAPIKEY=pubkey-XXXX TOEMAIL=email@XXXX.com go test
func TestService(t *testing.T) {
	dbFile := "auth.sdb"
	// create database
	db := sqlx.MustConnect("sqlite3", dbFile)
	// create user table
	db.MustExec(sqlCreateUserTable)

	// initialize mailgun
	mg := mailgun.NewMailgun(DOMAIN, APIKEY, PUBLICAPIKEY)

	// initialize new nonce service
	nonce := nonce.NewInMemoryService()

	// initialize new template system
	tpl := tmpl.NewTplSys("")

	// initialize new auth service
	auth = NewService(db, mg, nonce, tpl)

	// Run tests
	t.Run("NewUserLocal", func(t *testing.T) {
		u, err := auth.NewUserLocal(tUser.Email, tUser.Password, tUser.FirstName, tUser.LastName, tUser.IsSuperuser)
		if err != nil {
			t.Fatalf("Expected to add user to DB. Instead got the error: %v", err)
		}
		if u.Email != tUser.Email {
			t.Fatalf("Expected Email to be: %s. Instead got: %s", tUser.Email, u.Email)
		}
		if u.FirstName != tUser.FirstName {
			t.Fatalf("Expected FirstName to be: %s. Instead got: %s", tUser.FirstName, u.FirstName)
		}
		if u.LastName != tUser.LastName {
			t.Fatalf("Expected LastName to be: %s. Instead got: %s", tUser.LastName, u.LastName)
		}
		if u.IsSuperuser != tUser.IsSuperuser {
			t.Fatalf("Expected IsSuperuser to be: %s. Instead got: %s", tUser.IsSuperuser, u.IsSuperuser)
		}

		// Clean Up (removed the user we just added)
		tx := db.MustBegin()
		tx.MustExec("DELETE FROM user WHERE id=?", u.ID)
		tx.Commit()
	})

	t.Run("NewUserLocalDuplicate", func(t *testing.T) {
		u, err := auth.NewUserLocal(tUser.Email, tUser.Password, tUser.FirstName, tUser.LastName, tUser.IsSuperuser)
		if err != nil {
			t.Fatalf("Expected to add user to DB. Instead got the error: %v", err)
		}
		_, err = auth.NewUserLocal(tUser.Email, tUser.Password, tUser.FirstName, tUser.LastName, tUser.IsSuperuser)
		if err != ErrAlreadyExists {
			t.Fatalf("Expected to get error: ErrAlreadyExists. Instead got: %v", err)
		}

		// Clean Up (removed the user we just added)
		tx := db.MustBegin()
		tx.MustExec("DELETE FROM user WHERE id=?", u.ID)
		tx.Commit()
	})

	t.Run("NewUserLocalMalformed", func(t *testing.T) {
		var err error
		_, err = auth.NewUserLocal("", tUser.Password, tUser.FirstName, tUser.LastName, tUser.IsSuperuser)
		if err == nil {
			t.Fatal("Expected to get an error! Instead got: nil")
		}
		_, err = auth.NewUserLocal(tUser.Email, "", tUser.FirstName, tUser.LastName, tUser.IsSuperuser)
		if err == nil {
			t.Fatal("Expected to get an error! Instead got: nil")
		}
		_, err = auth.NewUserLocal(tUser.Email, tUser.Password, "", tUser.LastName, tUser.IsSuperuser)
		if err == nil {
			t.Fatal("Expected to get an error! Instead got: nil")
		}
		_, err = auth.NewUserLocal(tUser.Email, tUser.Password, tUser.FirstName, "", tUser.IsSuperuser)
		if err == nil {
			t.Fatal("Expected to get an error! Instead got: nil")
		}
		_, err = auth.NewUserLocal("   ", tUser.Password, tUser.FirstName, tUser.LastName, tUser.IsSuperuser)
		if err == nil {
			t.Fatal("Expected to get an error! Instead got: nil")
		}
		_, err = auth.NewUserLocal(tUser.Email, "   ", tUser.FirstName, tUser.LastName, tUser.IsSuperuser)
		if err == nil {
			t.Fatal("Expected to get an error! Instead got: nil")
		}
		_, err = auth.NewUserLocal(tUser.Email, tUser.Password, "   ", tUser.LastName, tUser.IsSuperuser)
		if err == nil {
			t.Fatal("Expected to get an error! Instead got: nil")
		}
		_, err = auth.NewUserLocal(tUser.Email, tUser.Password, tUser.FirstName, "   ", tUser.IsSuperuser)
		if err == nil {
			t.Fatal("Expected to get an error! Instead got: nil")
		}
	})

	t.Run("GetUser", func(t *testing.T) {
		u, err := auth.NewUserLocal(tUser.Email, tUser.Password, tUser.FirstName, tUser.LastName, tUser.IsSuperuser)
		if err != nil {
			t.Fatalf("Expected to add user to DB. Instead got the error: %v", err)
		}

		_, err = auth.GetUser(u.ID)
		if err != nil {
			t.Fatalf("Expected to get user from DB. Instead got the error: %v", err)
		}

		_, err = auth.GetUser(uuid.Nil)
		if err != ErrInvalidID {
			t.Fatalf("Expected to get an Invalid ID error.")
		}

		_, err = auth.GetUser(uuid.NewV4())
		if err != ErrUserNotFound {
			t.Fatalf("Expected to get ErrUserNotFound error.")
		}

		// Clean Up (removed the user we just added)
		tx := db.MustBegin()
		tx.MustExec("DELETE FROM user WHERE id=?", u.ID)
		tx.Commit()
	})

	t.Run("DeleteUser", func(t *testing.T) {
		u, err := auth.NewUserLocal(tUser.Email, tUser.Password, tUser.FirstName, tUser.LastName, tUser.IsSuperuser)
		if err != nil {
			t.Fatalf("Expected to add user to DB. Instead got the error: %v", err)
		}

		_, err = auth.DeleteUser(u.ID)
		if err != nil {
			t.Fatalf("Expected to delete user from DB. Instead got the error: %v", err)
		}

		u2, err := auth.GetUser(u.ID)
		if err != nil {
			t.Fatalf("Expected to get user from DB. Instead got the error: %v", err)
		}
		if u2.IsDeleted == false {
			t.Fatalf("Expected user to be deleted.")
		}

		_, err = auth.DeleteUser(uuid.Nil)
		if err != ErrInvalidID {
			t.Fatalf("Expected to get an Invalid ID error.")
		}

		// Clean Up (removed the user we just added)
		tx := db.MustBegin()
		tx.MustExec("DELETE FROM user WHERE id=?", u.ID)
		tx.Commit()
	})

	t.Run("AuthenticateUser", func(t *testing.T) {
		u, err := auth.NewUserLocal(tUser.Email, tUser.Password, tUser.FirstName, tUser.LastName, tUser.IsSuperuser)
		if err != nil {
			t.Fatalf("Expected to add user to DB. Instead got the error: %v", err)
		}

		_, err = auth.AuthenticateUser(tUser.Email, tUser.Password)
		if err != nil {
			t.Fatalf("Expected to get user from DB. Instead got the error: %v", err)
		}

		_, err = auth.AuthenticateUser("", tUser.Password)
		if err == nil {
			t.Fatalf("Expected to get an Invalid Email error. Instead got the error: nil")
		}

		_, err = auth.AuthenticateUser(tUser.Email, "")
		if err != ErrInvalidPassword {
			t.Fatalf("Expected to get ErrInvalidPassword. Instead got the error: %v", err)
		}

		_, err = auth.AuthenticateUser("wrong@email.com", tUser.Password)
		if err != ErrIncorrectAuth {
			t.Fatalf("Expected to get ErrIncorrectAuth. Instead got the error: %v", err)
		}

		_, err = auth.AuthenticateUser(tUser.Email, " wrong-password ")
		if err != ErrIncorrectAuth {
			t.Fatalf("Expected to get ErrIncorrectAuth. Instead got the error: %v", err)
		}

		// Clean Up (removed the user we just added)
		tx := db.MustBegin()
		tx.MustExec("DELETE FROM user WHERE id=?", u.ID)
		tx.Commit()
	})

	// Run tests
	t.Run("Emails", func(t *testing.T) {
		t.Log(DOMAIN, APIKEY, PUBLICAPIKEY, EMAILTO)
		u, err := auth.NewUserLocal(EMAILTO, tUser.Password, tUser.FirstName, tUser.LastName, tUser.IsSuperuser)
		if err != nil {
			t.Fatalf("Expected to add user to DB. Instead got the error: %v", err)
		}

		err = auth.BeginPasswordReset(EMAILTO)
		if err != nil {
			t.Fatalf("Expected to Begin Password Reset Process. Instead got: %v", err)
		}
		n, err := nonce.Get("auth.PasswordReset", u.ID)
		if err != nil {
			t.Fatalf("Expected to get Nonce for auth.PasswordReset. Instead got error: %v", err)
		}
		_, err = auth.CompletePasswordReset(n.Token, EMAILTO, "NewTestPassword")
		if err != nil {
			t.Fatalf("Expected to Complete the Password Reset Process. Instead got error: %v", err)
		}

		// Clean Up (removed the user we just added)
		tx := db.MustBegin()
		tx.MustExec("DELETE FROM user WHERE id=?", u.ID)
		tx.Commit()
	})

	// Drop the Table(s) we created
	// Close the DB
	db.MustExec("drop table user;")
	db.Close()
	err := os.Remove(dbFile)
	if err != nil {
		t.Fatalf("Expected to remove dbFile: %s. Instead got the error: %v", dbFile, err)
	}
}

func init() {
	DOMAIN = os.Getenv("MGDOMAIN")
	APIKEY = os.Getenv("MGAPIKEY")
	PUBLICAPIKEY = os.Getenv("MGPUBLICAPIKEY")
	EMAILTO = os.Getenv("TOEMAIL")

	// need a default for this
	EMAILTO = strings.TrimSpace(EMAILTO)
	if len(EMAILTO) == 0 {
		EMAILTO = "test@example.com"
	}

	tUser = User{
		Email:       EMAILTO,
		Password:    "password",
		FirstName:   "Test",
		LastName:    "Human",
		IsSuperuser: false,
	}
}
