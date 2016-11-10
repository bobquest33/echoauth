//
// @project GeniusRabbit 2016
// @author Dmitry Ponomarev <demdxx@gmail.com> 2016
// @license MIT
//

// Example:
// goth.UseProviders(
// 	twitter.New(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), "http://localhost:3000/auth/twitter/callback"),
// )

package echoauth

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/labstack/echo"
	"github.com/markbates/goth"
)

// SessionName is the key used to access the session store.
const SessionName = "_gothic_session"

// Errors list
var (
	ErrUndefinedProvider = errors.New("Undefined provider name")
)

// Session interface
type Session interface {
	Get(key string) (interface{}, error)
	Set(key string, value interface{}) error
	Delete(key string) error
	Save(ctx echo.Context) error
}

// SessionStore session accessor
type SessionStore interface {
	Get(ctx echo.Context) (Session, error)
}

// Client OAuth authorize
type Client struct {
	DefaultProvider string
	Store           SessionStore
}

// Begin auth session
func (cli *Client) Begin(ctx echo.Context) error {
	url, err := cli.GetAuthURL(ctx)
	if err != nil {
		return ctx.String(http.StatusBadRequest, err.Error())
	}
	return ctx.Redirect(http.StatusFound, url)
}

// Callback from oauth server
func (cli *Client) Callback(fnk func(user goth.User, err error, ctx echo.Context) error) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		user, err := cli.GetUser(ctx)
		return fnk(user, err, ctx)
	}
}

// GetUser object for oauth response
func (cli *Client) GetUser(ctx echo.Context) (goth.User, error) {
	providerName := cli.getProviderName(ctx)
	if len(providerName) < 1 {
		return goth.User{}, ErrUndefinedProvider
	}

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return goth.User{}, err
	}

	session, err := cli.Store.Get(ctx)
	if nil != err {
		return goth.User{}, err
	}

	sessionData, err := session.Get(SessionName)
	if nil != err || nil == sessionData {
		return goth.User{}, err
	}

	session.Delete(SessionName)
	session.Save(ctx)

	sess, err := provider.UnmarshalSession(sessionData.(string))
	if err != nil {
		return goth.User{}, err
	}

	_, err = sess.Authorize(provider, url.Values(ctx.Request().URL().QueryParams()))
	if err != nil {
		return goth.User{}, err
	}

	return provider.FetchUser(sess)
}

// GetAuthURL starts the authentication process with the requested provided.
// It will return a URL that should be used to send users to.
//
// It expects to be able to get the name of the provider from the query parameters
// as either "provider" or ":provider".
//
// I would recommend using the BeginAuthHandler instead of doing all of these steps
// yourself, but that's entirely up to you.
func (cli *Client) GetAuthURL(ctx echo.Context) (string, error) {
	providerName := cli.getProviderName(ctx)
	if len(providerName) < 1 {
		return "", ErrUndefinedProvider
	}

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return "", err
	}

	sess, err := provider.BeginAuth(setState(ctx))
	if err != nil {
		return "", err
	}

	url, err := sess.GetAuthURL()
	if err != nil {
		return "", err
	}

	var session Session
	if session, err = cli.Store.Get(ctx); nil == err {
		if err = session.Set(SessionName, sess.Marshal()); nil == err {
			err = session.Save(ctx)
		}
	}
	return url, err
}

///////////////////////////////////////////////////////////////////////////////
/// Helpers
///////////////////////////////////////////////////////////////////////////////

func (cli *Client) getProviderName(ctx echo.Context) string {
	provider := ctx.Param("provider")
	if provider == "" {
		return cli.DefaultProvider
	}
	return provider
}

// setState sets the state string associated with the given request.
// If no state string is associated with the request, one will be generated.
// This state is sent to the provider and can be retrieved during the
// callback.
func setState(ctx echo.Context) string {
	if state := ctx.QueryParam("state"); len(state) > 0 {
		return state
	}
	return "state"
}

// getState gets the state returned by the provider during the callback.
// This is used to prevent CSRF attacks, see
// http://tools.ietf.org/html/rfc6749#section-10.12
func getState(ctx echo.Context) string {
	return ctx.QueryParam("state")
}
