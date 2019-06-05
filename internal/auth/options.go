package auth

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path"

	"github.com/buzzfeed/sso/internal/auth/providers"
	"github.com/buzzfeed/sso/internal/pkg/aead"
	"github.com/buzzfeed/sso/internal/pkg/groups"
	"github.com/buzzfeed/sso/internal/pkg/sessions"

	"github.com/datadog/datadog-go/statsd"
)

func newProvider(pc ProviderConfig) (providers.Provider, error) {
	p := &providers.ProviderData{
		ProviderSlug: pc.ProviderSlug,
		Scope:        pc.Scope,
		ClientID:     pc.ClientID,
		ClientSecret: pc.ClientSecret,
	}

	var singleFlightProvider providers.Provider
	switch pc.ProviderType {
	case providers.GoogleProviderName: // Google
		gpc := pc.GoogleProviderConfig
		p.ApprovalPrompt = gpc.ApprovalPrompt

		if gpc.ServiceAccountJSON != "" {
			_, err := os.Open(gpc.ServiceAccountJSON)
			if err != nil {
				return nil, fmt.Errorf("invalid Google credentials file: %s", gpc.ServiceAccountJSON)
			}
		}

		googleProvider, err := providers.NewGoogleProvider(p, gpc.AdminEmail, gpc.ServiceAccountJSON)
		if err != nil {
			return nil, err
		}

		cache := groups.NewFillCache(googleProvider.PopulateMembers, pc.GroupCacheConfig.RefreshTTL)
		googleProvider.GroupsCache = cache

		singleFlightProvider = providers.NewSingleFlightProvider(googleProvider)
	case providers.OktaProviderName:
		opc := pc.OktaProviderConfig

		oktaProvider, err := providers.NewOktaProvider(p, opc.OrgURL, opc.ServerID)
		if err != nil {
			return nil, err
		}

		tags := []string{"provider:okta"}
		cache := providers.NewGroupCache(oktaProvider, pc.GroupCacheConfig.ProviderTTL, oktaProvider.StatsdClient, tags)
		singleFlightProvider = providers.NewSingleFlightProvider(cache)
	case "test":
		return providers.NewTestProvider(nil), nil
	default:
		return nil, fmt.Errorf("unimplemented provider.type: %q", pc.ProviderType)
	}

	return singleFlightProvider, nil
}

// SetProvider is a function that takes a provider and assigns it to the authenticator.
func SetProvider(provider providers.Provider) func(*Authenticator) error {
	return func(a *Authenticator) error {
		a.provider = provider
		return nil
	}
}

// SetStatsdClient is function that takes in a statsd client and assigns it to the
// authenticator and provider.
func SetStatsdClient(statsdClient *statsd.Client) func(*Authenticator) error {
	return func(a *Authenticator) error {
		a.StatsdClient = statsdClient

		if a.provider != nil {
			a.provider.SetStatsdClient(statsdClient)
		}

		return nil
	}
}

// SetRedirectURL takes an identity provider slug to construct the
// url callback using the slug and configured redirect url.
func SetRedirectURL(slug string) func(*Authenticator) error {
	return func(a *Authenticator) error {
		a.redirectURL = &url.URL{
			Path: path.Join(slug, "callback"),
		}
		return nil
	}
}

// SetCookieStore sets the cookie store to use a miscreant cipher
func SetCookieStore(config Configuration, providerSlug string) func(*Authenticator) error {
	return func(a *Authenticator) error {
		decodedAuthCodeSecret, err := base64.StdEncoding.DecodeString(config.SessionConfig.AuthCodeSecret)
		if err != nil {
			return err
		}

		authCodeCipher, err := aead.NewMiscreantCipher([]byte(decodedAuthCodeSecret))
		if err != nil {
			return err
		}

		cc := config.SessionConfig.CookieConfig
		decodedCookieSecret, err := base64.StdEncoding.DecodeString(cc.Secret)
		if err != nil {
			return err
		}

		cookieName := fmt.Sprintf("%s_%s", cc.Name, providerSlug)
		cookieStore, err := sessions.NewCookieStore(cookieName,
			sessions.CreateMiscreantCookieCipher(decodedCookieSecret),
			func(c *sessions.CookieStore) error {
				c.CookieDomain = cc.Domain
				c.CookieHTTPOnly = cc.HTTPOnly
				c.CookieExpire = cc.Expire
				c.CookieSecure = cc.Secure
				return nil
			})

		if err != nil {
			return err
		}

		a.csrfStore = cookieStore
		a.sessionStore = cookieStore
		a.AuthCodeCipher = authCodeCipher
		return nil
	}
}
