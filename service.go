package auth

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"html/template"
	"net/mail"
	"strings"
	"time"

	"github.com/bryanjeal/go-helpers"
	"github.com/bryanjeal/go-nonce"
	tmpl "github.com/bryanjeal/go-tmpl"

	// handle mysql database
	_ "github.com/go-sql-driver/mysql"
	// handle sqlite3 database
	_ "github.com/mattn/go-sqlite3"

	"github.com/golang/glog"
	"github.com/jmoiron/sqlx"
	"github.com/markbates/goth"
	"github.com/satori/go.uuid"
	"gopkg.in/mailgun/mailgun-go.v1"
)

// Errors
var (
	ErrInconsistentIDs = errors.New("inconsistent IDs")
	ErrAlreadyExists   = errors.New("already exists")
	ErrUserNotFound    = errors.New("user not found")
	ErrInvalidID       = errors.New("null id")
	ErrInvalidPassword = errors.New("password cannot blank or all spaces")
	ErrInvalidName     = errors.New("name cannot be blank or all spaces")
	ErrIncorrectAuth   = errors.New("incorrect email or password")
	ErrTodo            = errors.New("unimplemented feature or function")
)

// Service is the interface that provides auth methods.
type Service interface {
	// NewUserLocal registers a new user by a local account (email and password)
	NewUserLocal(email, password, firstName, lastName string, isSuperuser bool) (User, error)

	// NewUserProvider registers a new user by some oAuth Provider
	NewUserProvider(user goth.User, isSuperuser bool) (User, error)

	// UserAddProvider associates a new oAuth Provider with the user account
	UserAddProvider(id uuid.UUID, user goth.User) (User, error)

	// GetUser gets a user account by their ID
	GetUser(id uuid.UUID) (User, error)

	// UpdateUser update the user's details
	UpdateUser(u User) (User, error)

	// DeleteUser flag a user as deleted
	DeleteUser(id uuid.UUID) (User, error)

	// AuthenticateUser logs in a Local User with an email and password
	AuthenticateUser(email, password string) (User, error)

	// Start the Password Reset process
	BeginPasswordReset(email string) error

	// Complete the Password Reset process
	CompletePasswordReset(token, email, password string) (User, error)
}

// authService satisfies the auth.Service interface
type authService struct {
	db    *sqlx.DB
	mg    mailgun.Mailgun
	nonce nonce.Service
	tpl   *tmpl.TplSys
}

// NewService creates an Auth Service that connects to provided DB information
func NewService(db *sqlx.DB, mg mailgun.Mailgun, nonce nonce.Service, tpl *tmpl.TplSys) Service {
	s := &authService{
		db:    db,
		mg:    mg,
		nonce: nonce,
		tpl:   tpl,
	}

	// TODO
	// Move hardcoded Template Strings to templates.go
	template.Must(s.tpl.AddTemplate("auth.baseHTMLEmailTemplate", "", baseHTMLEmailTemplate))
	template.Must(s.tpl.AddTemplate("auth.NewUserEmail", "auth.baseHTMLEmailTemplate", `{{define "title"}}Welcome New User{{end}}{{define "content"}}<p style="margin:0;padding:1em 0 0 0;line-height:1.5em;font-family:Helvetica Neue, Helvetica, Arial, sans-serif;font-size:14px;color:#000;"> Hello %recipient.firstname% %recipient.lastname%, <br/> <br/> Welcome to our service. Thank you for signing up.<br/> <br/> </p>{{end}}`))
	template.Must(s.tpl.AddTemplate("auth.PasswordResetEmail", "auth.baseHTMLEmailTemplate", `{{define "title"}}Password Reset{{end}}{{define "content"}}<p style="margin:0;padding:1em 0 0 0;line-height:1.5em;font-family:Helvetica Neue, Helvetica, Arial, sans-serif;font-size:14px;color:#000;"> Hello %recipient.firstname% %recipient.lastname%, <br/> <br/> Forgot your password? No problem! <br/> <br/> To reset your password, click the following link: <br/> <a href="https://www.example.com/auth/password-reset/%recipient.token%">Reset Password</a> <br/> <br/> If you did not request to have your password reset you can safely ignore this email. Rest assured your customer account is safe. <br/> <br/> </p>{{end}}`))
	template.Must(s.tpl.AddTemplate("auth.PasswordResetConfirmEmail", "auth.baseHTMLEmailTemplate", `{{define "title"}}Password Reset Complete{{end}}{{define "content"}}<p style="margin:0;padding:1em 0 0 0;line-height:1.5em;font-family:Helvetica Neue, Helvetica, Arial, sans-serif;font-size:14px;color:#000;"> Hello %recipient.firstname% %recipient.lastname%, <br/> <br/> Your account's password was recently changed. <br/> <br/> </p>{{end}}`))

	return s
}

func (s *authService) NewUserLocal(email, password, firstName, lastName string, isSuperuser bool) (User, error) {
	eUser := User{}
	err := s.db.Get(&eUser, "SELECT * FROM user WHERE email=$1", email)
	if err == nil {
		return User{}, ErrAlreadyExists
	} else if err != sql.ErrNoRows {
		return User{}, err
	}

	// get current time
	t := time.Now()

	// hash password
	hashed, err := helpers.Crypto.BCryptPasswordHasher([]byte(password))
	hashedB64 := base64.StdEncoding.EncodeToString(hashed)

	// TODO:
	// Have users activate their account via an email
	u := User{
		Email:       email,
		Password:    hashedB64,
		FirstName:   firstName,
		LastName:    lastName,
		IsSuperuser: isSuperuser,
		IsActive:    true,
		IsDeleted:   false,
		CreatedAt:   t,
		UpdatedAt:   t,
		DeletedAt:   time.Time{},
		AvatarURL:   "",
		newPassword: true,
		rawPassword: password,
	}

	// Save user to DB
	err = s.saveUser(&u)
	if err != nil {
		return User{}, err
	}

	// Create Email Message
	msg := s.mg.NewMessage(NewUserEmail.From, NewUserEmail.Subject, NewUserEmail.PlainText, u.Email)
	b, err := s.tpl.ExecuteTemplate(NewUserEmail.TplName, u)
	if err != nil {
		glog.Errorf("Error creating HTML Email. Got error: %v", err)
		return u, nil
	}
	msg.SetHtml(string(b))

	// Add custom information via AddRecipientAndVariables
	err = msg.AddRecipientAndVariables(u.Email, map[string]interface{}{
		"firstname": u.FirstName,
		"lastname":  u.LastName,
	})
	if err != nil {
		glog.Errorf("Error with AddRecipientAndVariables. Got error: %v", err)
		return u, nil
	}

	// Send Message
	_, _, err = s.mg.Send(msg)
	if err != nil {
		glog.Errorf("Error sending email. Got error: %v", err)
		return u, nil
	}

	return u, nil
}

func (s *authService) NewUserProvider(u goth.User, isSuperuser bool) (User, error) {
	// TODO:
	// Implement Feature
	return User{}, ErrTodo
}

func (s *authService) UserAddProvider(id uuid.UUID, u goth.User) (User, error) {
	// TODO:
	// Implement Feature
	return User{}, ErrTodo
}

func (s *authService) GetUser(id uuid.UUID) (User, error) {
	if id == uuid.Nil {
		return User{}, ErrInvalidID
	}

	u := User{}
	err := s.db.Get(&u, "SELECT * FROM user WHERE id=$1", id)
	if err != nil && err != sql.ErrNoRows {
		return User{}, err
	} else if err == sql.ErrNoRows {
		return User{}, ErrUserNotFound
	}

	return u, nil
}

func (s *authService) UpdateUser(u User) (User, error) {
	eUser := User{}
	err := s.db.Get(&eUser, "SELECT * FROM user WHERE email=$1", u.Email)
	if err == sql.ErrNoRows {
		return User{}, ErrUserNotFound
	} else if err != nil {
		return User{}, err
	}

	if !uuid.Equal(eUser.ID, u.ID) {
		return User{}, ErrInconsistentIDs
	}

	err = s.saveUser(&u)
	if err != nil {
		return User{}, err
	}

	return u, nil
}

func (s *authService) DeleteUser(id uuid.UUID) (User, error) {
	u, err := s.GetUser(id)
	if err != nil {
		return User{}, err
	}

	u.IsDeleted = true
	u.DeletedAt = time.Now()

	// Save user to DB
	err = s.saveUser(&u)
	if err != nil {
		return User{}, err
	}

	return u, nil
}

func (s *authService) AuthenticateUser(email, password string) (User, error) {
	// Check Email
	e, err := mail.ParseAddress(email)
	if err != nil {
		return User{}, err
	}

	// Check Password
	p := strings.TrimSpace(password)
	if len(p) == 0 {
		return User{}, ErrInvalidPassword
	}

	// Get user from database
	u, err := s.getUserByEmail(e.Address)
	if err != nil {
		return User{}, err
	}

	// check password
	hashed, err := base64.StdEncoding.DecodeString(u.Password)
	if err != nil {
		return User{}, err
	}
	err = helpers.Crypto.BCryptCompareHashPassword(hashed, []byte(password))
	if err != nil {
		return User{}, ErrIncorrectAuth
	}
	return u, nil
}

func (s *authService) BeginPasswordReset(email string) error {
	// Check email
	e, err := mail.ParseAddress(email)
	if err != nil {
		return err
	}

	// Get user from database
	u, err := s.getUserByEmail(e.Address)
	if err != nil {
		return err
	}

	// create nonce for reset token
	n, err := s.nonce.New("auth.PasswordReset", u.ID, time.Hour*3)
	if err != nil {
		return err
	}

	// Create Email Message
	msg := s.mg.NewMessage(PasswordResetEmail.From, PasswordResetEmail.Subject, PasswordResetEmail.PlainText, u.Email)
	b, err := s.tpl.ExecuteTemplate(PasswordResetEmail.TplName, u)
	if err != nil {
		return err
	}
	msg.SetHtml(string(b))

	// Add custom information via AddRecipientAndVariables
	err = msg.AddRecipientAndVariables(u.Email, map[string]interface{}{
		"token":     n.Token,
		"firstname": u.FirstName,
		"lastname":  u.LastName,
	})
	if err != nil {
		return err
	}

	// Send Message
	_, _, err = s.mg.Send(msg)
	if err != nil {
		return err
	}

	return nil
}

func (s *authService) CompletePasswordReset(token, email, password string) (User, error) {
	// Check email
	e, err := mail.ParseAddress(email)
	if err != nil {
		return User{}, err
	}

	// Get User
	u, err := s.getUserByEmail(e.Address)
	if err != nil {
		return User{}, err
	}

	// Check and Use Token
	_, err = s.nonce.CheckThenConsume(token, "auth.PasswordReset", u.ID)
	if err != nil {
		return User{}, err
	}

	// hash password
	hashed, err := helpers.Crypto.BCryptPasswordHasher([]byte(password))
	hashedB64 := base64.StdEncoding.EncodeToString(hashed)

	u.Password = hashedB64
	u.newPassword = true
	u.rawPassword = password

	err = s.saveUser(&u)
	if err != nil {
		return User{}, err
	}

	// Create Email Message
	msg := s.mg.NewMessage(PasswordResetConfirmEmail.From, PasswordResetConfirmEmail.Subject, PasswordResetConfirmEmail.PlainText, u.Email)
	b, err := s.tpl.ExecuteTemplate(PasswordResetConfirmEmail.TplName, u)
	if err != nil {
		glog.Errorf("Error creating HTML Email. Got error: %v", err)
		return u, nil
	}
	msg.SetHtml(string(b))

	// Add custom information via AddRecipientAndVariables
	err = msg.AddRecipientAndVariables(u.Email, map[string]interface{}{
		"firstname": u.FirstName,
		"lastname":  u.LastName,
	})
	if err != nil {
		glog.Errorf("Error with AddRecipientAndVariables. Got error: %v", err)
		return u, nil
	}

	// Send Message
	_, _, err = s.mg.Send(msg)
	if err != nil {
		glog.Errorf("Error sending email. Got error: %v", err)
		return u, nil
	}

	return u, nil
}

// getUserByEmail gets a user from the database by email address
func (s *authService) getUserByEmail(email string) (User, error) {
	u := User{}
	err := s.db.Get(&u, "SELECT * FROM user WHERE email=$1", email)
	if err != nil && err != sql.ErrNoRows {
		return User{}, err
	} else if err == sql.ErrNoRows {
		return User{}, ErrIncorrectAuth
	}

	return u, nil
}

// saveUser saves a new user to the database or updates an existing user
func (s *authService) saveUser(u *User) error {
	if err := u.Validate(); err != nil {
		return err
	}

	var sqlExec string

	// if id is nil then it is a new user
	if u.ID == uuid.Nil {
		// generate ID
		u.ID = uuid.NewV4()
		sqlExec = `INSERT INTO user 
		(id, email, password, firstname, lastname, is_superuser, is_active, is_deleted, created_at, updated_at, deleted_at, avatar_url) 
		VALUES (:id, :email, :password, :firstname, :lastname, :is_superuser, :is_active, :is_deleted, :created_at, :updated_at, :deleted_at, :avatar_url)`
	} else {
		sqlExec = `UPDATE user SET email=:email, password=:password, firstname=:firstname, lastname=:lastname, is_superuser=:is_superuser, 
		is_active=:is_active, is_deleted=:is_deleted, created_at=:created_at, updated_at=:updated_at, deleted_at=:deleted_at, avatar_url=:avatar_url WHERE id=:id`
	}

	tx, err := s.db.Beginx()
	if err != nil {
		return err
	}
	_, err = tx.NamedExec(sqlExec, &u)
	if err != nil {
		tx.Rollback()
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}
