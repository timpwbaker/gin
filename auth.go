// Copyright 2014 Manu Martinez-Almeida.  All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package gin

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// AuthUserKey is the cookie name for user credential in basic auth.
const AuthUserKey = "user"

// Accounts defines a key/value for user/pass list of authorized logins.
type Accounts map[string]string

func (a Accounts) searchCredential(authValue string) (string, bool) {
	if authValue == "" {
		return "", false
	}

	providedUser, providedPassword, err := decodeBasicAuth(authValue)
	if err != nil {
		return "", false
	}

	for user, pass := range a {
		if strings.ToLower(user) == strings.ToLower(providedUser) &&
			pass == providedPassword {
			return user, true
		}
	}

	return "", false
}

// BasicAuthForRealm returns a Basic HTTP Authorization middleware. It takes as arguments a map[string]string where
// the key is the user name and the value is the password, as well as the name of the Realm.
// If the realm is empty, "Authorization Required" will be used by default.
// (see http://tools.ietf.org/html/rfc2617#section-1.2)
func BasicAuthForRealm(accounts Accounts, realm string) HandlerFunc {
	if realm == "" {
		realm = "Authorization Required"
	}
	realm = "Basic realm=" + strconv.Quote(realm)
	return func(c *Context) {
		// Search user in the slice of allowed credentials
		user, found := accounts.searchCredential(c.requestHeader("Authorization"))
		if !found {
			// Credentials doesn't match, we return 401 and abort handlers chain.
			c.Header("WWW-Authenticate", realm)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// The user credentials was found, set user's id to key AuthUserKey in this context, the user's id can be read later using
		// c.MustGet(gin.AuthUserKey).
		c.Set(AuthUserKey, user)
	}
}

// BasicAuth returns a Basic HTTP Authorization middleware. It takes as argument a map[string]string where
// the key is the user name and the value is the password.
func BasicAuth(accounts Accounts) HandlerFunc {
	return BasicAuthForRealm(accounts, "")
}

func decodeBasicAuth(authString string) (string, string, *Error) {
	auth := strings.SplitN(authString, " ", 2)

	if len(auth) != 2 || auth[0] != "Basic" {
		return "", "", &Error{
			Err:  fmt.Errorf("httpbasic incorrect format"),
			Type: ErrorTypePrivate,
		}
	}

	payload, err := base64.StdEncoding.DecodeString(auth[1])
	if err != nil {
		return "", "", &Error{
			Err:  fmt.Errorf("httpbasic could not decode"),
			Type: ErrorTypePrivate,
		}
	}

	values := strings.SplitN(string(payload), ":", 2)

	return values[0], values[1], nil
}

func secureCompare(given, actual string) bool {
	if subtle.ConstantTimeEq(int32(len(given)), int32(len(actual))) == 1 {
		return subtle.ConstantTimeCompare([]byte(given), []byte(actual)) == 1
	}
	// Securely compare actual to itself to keep constant time, but always return false.
	return subtle.ConstantTimeCompare([]byte(actual), []byte(actual)) == 1 && false
}
