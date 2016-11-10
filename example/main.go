//
// @project GeniusRabbit 2016
// @author Dmitry Ponomarev <demdxx@gmail.com> 2016
// @license MIT
//

package main

import (
	"fmt"
	"net/http"
	"os"

	session "github.com/ipfans/echo-session"
	"github.com/labstack/echo"
	"github.com/labstack/echo/engine/standard"
	"github.com/labstack/echo/middleware"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/facebook"

	echoauth ".."
)

var (
	oauth2Client = echoauth.Client{
		DefaultProvider: "facebook",
		Store:           sessionStoreFnk(sessionStoreGet),
	}
)

func main() {
	// Init oauth provider
	goth.UseProviders(
		facebook.New(
			os.Getenv("FACEBOOK_KEY"),
			os.Getenv("FACEBOOK_SECRET"),
			"http://localhost:3000/auth/facebook/callback",
		),
	)

	serv := echo.New()
	serv.Use(middleware.Logger())
	serv.Use(middleware.Recover())
	store := session.NewCookieStore([]byte("secret"))
	serv.Use(session.Sessions("sessid", store))

	serv.Get("/", func(ctx echo.Context) error {
		return ctx.Redirect(http.StatusFound, "/auth/facebook")
	})
	serv.Get("/auth/:provider", oauth2Client.Begin)
	serv.Get("/auth/:provider/callback", oauth2Client.Callback(func(user goth.User, err error, ctx echo.Context) error {
		return ctx.JSON(http.StatusOK, user)
	}))

	fmt.Println("Run server: http://localhost:3000")
	serv.Run(standard.New(":3000"))
}

///////////////////////////////////////////////////////////////////////////////
/// Session
///////////////////////////////////////////////////////////////////////////////

// Session wrapper
type Session struct {
	session.Session
}

// Get returns the session value associated to the given key.
func (s Session) Get(key string) (interface{}, error) {
	return s.Session.Get(key), nil
}

// Set sets the session value associated to the given key.
func (s Session) Set(key string, value interface{}) error {
	s.Session.Set(key, value)
	return nil
}

// Delete removes the session value associated to the given key.
func (s Session) Delete(key string) error {
	s.Session.Delete(key)
	return nil
}

// Save saves all sessions used during the current request.
func (s Session) Save(ctx echo.Context) error {
	return s.Session.Save()
}

func sessionStoreGet(ctx echo.Context) (echoauth.Session, error) {
	return &Session{
		Session: session.Default(ctx),
	}, nil
}

type sessionStoreFnk func(ctx echo.Context) (echoauth.Session, error)

func (f sessionStoreFnk) Get(ctx echo.Context) (echoauth.Session, error) {
	return f(ctx)
}
