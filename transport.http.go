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
	"net/http"
	"strings"

	"github.com/bryanjeal/go-helpers"
	tmpl "github.com/bryanjeal/go-tmpl"

	"github.com/golang/glog"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

// CtxKey is where other libraries can find the AuthCtx struct within http.Request.Context()
const CtxKey = "auth.ctx"

const sessKey = "auth.session"

// httpViewHandler holds everything the Auth HTTP Views need to work
type httpViewHandler struct {
	auth    Service
	next    http.Handler
	session sessions.Store
	tpl     *tmpl.TplSys
	router  *mux.Router
}

type authCtx struct {
	tmpl.Ctx
	User User
}

// MakeHTTPHandler returns a handler that exposes part or all of the service over predefined HTTP paths.
func MakeHTTPHandler(auth Service, urlPrefix string, baseTmplName string, tpl *tmpl.TplSys, store sessions.Store) http.Handler {
	h := &httpViewHandler{
		auth:    auth,
		tpl:     tpl,
		session: store,
	}

	// make sure prefix is valid
	urlPrefix = "/" + strings.Trim(urlPrefix, "/")

	// Add templates to Store
	for k, v := range HTMLTemplates {
		_, err := h.tpl.AddTemplate(k, baseTmplName, v)
		if err != nil {
			glog.Fatalf("Expected to add Template \"%s\" to TplSys. Instead got error: %v", k, err)
		}
	}

	// Add routes
	r := mux.NewRouter()
	r = r.PathPrefix(urlPrefix).Subrouter()
	h.router = r

	/* need the following
	ROUTE	METHOD					Service Call
	/login GET
	/login POST 					AuthenticateUser
	/logout
	/register GET
	/register POST					NewUserLocal
	/forgot-password GET
	/forgot-password POST			BeginPasswordReset
	/forgot-password/{token} GET
	/forgot-password/{token} POST	CompletePasswordReset
	/update GET
	/update POST		 			UpdateUser
	/delete GET
	*/

	r.HandleFunc("/login/", h.Login).Methods("GET").Name("login")
	r.HandleFunc("/login/", h.LoginPost).Methods("POST")
	r.HandleFunc("/logout/", h.Logout).Methods("GET").Name("logout")
	r.HandleFunc("/register/", h.Register).Methods("GET").Name("register")

	csrfKey, err := helpers.Crypto.GenerateRandomKey(32)
	if err != nil {
		glog.Fatalf("Expected to generate random key for CSRF. Instead got error: %v", err)
	}
	return h.addMiddleware(csrf.Protect(csrfKey)(r))
}

// Login Displays Login Template or redirects to "/" if already logged in
// Passes the following additional data to the template:
// • LoginURL
// • RegisterURL
func (h *httpViewHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx, err := getAuthCtx(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if ctx.User.IsActive {
		http.Redirect(w, r, "/", 302)
		return
	}

	loginURL, err := h.router.Get("login").URL()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	registerURL, err := h.router.Get("register").URL()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ctx.Data["LoginURL"] = loginURL.String()
	ctx.Data["RegisterURL"] = registerURL.String()

	page, err := h.tpl.ExecuteTemplate("auth.Tpl.Login", ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(page)
}

// LoginPost Handles POST submission of the Login Template
func (h *httpViewHandler) LoginPost(w http.ResponseWriter, r *http.Request) {
	// get or create session
	sess, _ := h.session.Get(r, sessKey)

	email := r.FormValue("email")
	password := r.FormValue("password")

	u, err := h.auth.AuthenticateUser(email, password)
	if err == ErrIncorrectAuth {
		sess.AddFlash("Error: Username and/or Password was incorrect!", "error")
		sess.Save(r, w)
		http.Redirect(w, r, "/login", 302)
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sess.Values["user"] = u
	sess.Save(r, w)

	http.Redirect(w, r, "/", 302)
}

// Logout handles removing session data
func (h *httpViewHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sess, _ := h.session.Get(r, sessKey)
	sess.AddFlash("You have been logged out.")
	delete(sess.Values, "user")
	sess.Save(r, w)

	url, err := h.router.Get("login").URL()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, url.String(), 302)
}

// Register Displays Registration Template or redirects to "/" if already logged in
// Passes the following additional data to the template:
// • LoginURL
// • RegisterURL
func (h *httpViewHandler) Register(w http.ResponseWriter, r *http.Request) {
	ctx, err := getAuthCtx(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	if ctx.User.IsActive {
		http.Redirect(w, r, "/", 302)
		return
	}

	loginURL, err := h.router.Get("login").URL()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	registerURL, err := h.router.Get("register").URL()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ctx.Data["LoginURL"] = loginURL.String()
	ctx.Data["RegisterURL"] = registerURL.String()

	w.Write([]byte("Register Page"))
}

// getAuthCtx is a helper to get or create a new Auth.Ctx
func getAuthCtx(r *http.Request) (*authCtx, error) {
	var ctx *authCtx
	var ok bool

	ctxRaw, err := helpers.Ctx.Http.CtxGet(r, CtxKey)
	if err != nil && err != helpers.ErrCtxNoValue {
		return ctx, err
	}

	if err != helpers.ErrCtxNoValue {
		if ctx, ok = ctxRaw.(*authCtx); !ok {
			ctx = &authCtx{
				Ctx: tmpl.Ctx{
					Data: make(map[string]interface{}),
				},
			}
		}
	}

	return ctx, nil
}

// addMiddleware just passes the next http.Handler to our httpViewHandler struct
func (h *httpViewHandler) addMiddleware(next http.Handler) http.Handler {
	h.next = next
	return h
}

// ServeHTTP satisfies http.Handler interface. This gathers various items we need into a common context.
func (h *httpViewHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess, _ := h.session.Get(r, sessKey)

	ctx, err := getAuthCtx(r)
	if err != nil {
		glog.Errorf("Expected to get Auth Context. Instead got error: %v", err)
	}

	ctx.Flashes = sess.Flashes()
	ctx.FlashesInfo = sess.Flashes("info")
	ctx.FlashesWarn = sess.Flashes("warn")
	ctx.FlashesError = sess.Flashes("error")
	ctx.CsrfToken = csrf.Token(r)

	usrRaw := sess.Values["user"]
	usr, ok := usrRaw.(User)
	if !ok {
		usr = User{}
	}
	ctx.User = usr

	r = helpers.Ctx.Http.CtxSave(r, CtxKey, ctx)
	sess.Save(r, w)
	h.next.ServeHTTP(w, r)
}
