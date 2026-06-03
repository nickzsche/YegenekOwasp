package httpengine

import (
	"net/http"
)

type AuthMethod string

const (
	AuthMethodBearer AuthMethod = "bearer"
	AuthMethodCookie AuthMethod = "cookie"
	AuthMethodHeader AuthMethod = "header"
	AuthMethodBasic  AuthMethod = "basic"
)

type AuthConfig struct {
	Method      AuthMethod
	Token       string
	TokenHeader string
	Cookies     []*http.Cookie
	Headers     map[string]string
	Username    string
	Password    string
}

func NewAuthConfig() *AuthConfig {
	return &AuthConfig{
		Method:      AuthMethodBearer,
		TokenHeader: "Authorization",
	}
}

func (a *AuthConfig) Apply(req *http.Request) {
	switch a.Method {
	case AuthMethodBearer:
		if a.Token != "" {
			header := a.TokenHeader
			if header == "" {
				header = "Authorization"
			}
			req.Header.Set(header, "Bearer "+a.Token)
		}
	case AuthMethodHeader:
		for k, v := range a.Headers {
			req.Header.Set(k, v)
		}
	case AuthMethodCookie:
		for _, c := range a.Cookies {
			req.AddCookie(c)
		}
	case AuthMethodBasic:
		if a.Username != "" {
			req.SetBasicAuth(a.Username, a.Password)
		}
	}

	// Always apply additional headers
	for k, v := range a.Headers {
		req.Header.Set(k, v)
	}
}
