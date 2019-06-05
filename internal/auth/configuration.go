package auth

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/micro/go-micro/config"
	"github.com/micro/go-micro/config/source/env"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/xerrors"
)

// DefaultAuthConfig specifies all the defaults used to configure sso-auth
func DefaultAuthConfig() Configuration {
	return Configuration{
		ServerConfig: ServerConfig{
			Port: 4180,
			TCPConfig: TCPConfig{
				WriteTimeout: 30 * time.Second,
				ReadTimeout:  30 * time.Second,
			},
			Timeout: 2 * time.Second,
		},
		SessionConfig: SessionConfig{
			SessionLifetimeTTL: (30 * 24) * time.Hour,
			CookieConfig: CookieConfig{
				Expire:   (7 * 24) * time.Hour,
				Name:     "_sso_auth",
				Secure:   true,
				HTTPOnly: true,
			},
		},
		MetricsConfig: MetricsConfig{
			RequestLogging: true,
		},

		// we provide no defaults for these right now
		ProviderConfigs: map[string]ProviderConfig{},
		ClientConfig:    ClientConfig{},
		AuthorizeConfig: AuthorizeConfig{},
	}
}

// Validator interface ensures all config structs implement Validate()
type Validator interface {
	Validate() error
}

var (
	_ Validator = Configuration{}
	_ Validator = ProviderConfig{}
	_ Validator = ClientConfig{}
	_ Validator = AuthorizeConfig{}
	_ Validator = ServerConfig{}
	_ Validator = MetricsConfig{}
	_ Validator = GoogleProviderConfig{}
	_ Validator = OktaProviderConfig{}
	_ Validator = CookieConfig{}
	_ Validator = TCPConfig{}
	_ Validator = StatsdConfig{}
)

// Configuration is the parent struct that holds all the configuration
type Configuration struct {
	ProviderConfigs map[string]ProviderConfig `mapstructure:"provider"`
	ClientConfig    ClientConfig              `mapstructure:"client"`

	AuthorizeConfig AuthorizeConfig `mapstructure:"authorize"`
	SessionConfig   SessionConfig   `mapstructure:"session"`
	ServerConfig    ServerConfig    `mapstructure:"server"`
	MetricsConfig   MetricsConfig   `mapstructrue:"metrics"`
}

func (c Configuration) Validate() error {
	for slug, providerConfig := range c.ProviderConfigs {
		if err := providerConfig.Validate(); err != nil {
			return xerrors.Errorf("invalid provider.%s config: %w", slug, err)
		}
	}

	if err := c.ClientConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid client config: %w", err)
	}

	if err := c.SessionConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid session config: %w", err)
	}

	if err := c.ServerConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid server config: %w", err)
	}

	if err := c.AuthorizeConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid authorize config: %w", err)
	}

	if err := c.MetricsConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid metrics config: %w", err)
	}

	return nil
}

type ProviderConfig struct {
	ProviderType string `mapstructure:"type"`
	ProviderSlug string `mapstructure:"slug"`
	ClientID     string `mapstructure:"id"`
	ClientSecret string `mapstructure:"secret"`
	Scope        string `mapstructure:"scope"`

	// provider specific
	GoogleProviderConfig GoogleProviderConfig `mapstructure:"google"`
	OktaProviderConfig   OktaProviderConfig   `mapstructure:"okta"`

	// caching
	GroupCacheConfig GroupCacheConfig `mapstructure:"groupcache"`
}

func (pc ProviderConfig) Validate() error {
	if pc.ProviderType == "" {
		return xerrors.Errorf("invalid provider.type: %q", pc.ProviderType)
	}

	// TODO: more validation of provider slug, should conform to simple character space
	if pc.ProviderSlug == "" {
		return xerrors.Errorf("invalid provider.slug: %q", pc.ProviderSlug)
	}

	if pc.ClientID == "" {
		return xerrors.Errorf("invalid provider.id: %q", pc.ClientID)
	}

	if pc.ClientSecret == "" {
		return xerrors.Errorf("invalid provider.secret: %q", "<omitted>")
	}

	switch pc.ProviderType {
	case "google":
		if err := pc.GoogleProviderConfig.Validate(); err != nil {
			return xerrors.Errorf("invalid provider.google config: %w", err)
		}
	case "okta":
		if err := pc.OktaProviderConfig.Validate(); err != nil {
			return xerrors.Errorf("invalid provider.okta config: %w", err)
		}
	case "test":
		break
	default:
		return xerrors.Errorf("unknown provider.type: %q", pc.ProviderType)
	}

	if err := pc.GroupCacheConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid provider.groupcache config: %w", err)
	}

	return nil
}

type GoogleProviderConfig struct {
	AdminEmail         string `mapstructure:"admin-email"`
	ServiceAccountJSON string `mapstructure:"service-account-json"`
	ApprovalPrompt     string `mapstructure:"approval-prompt"`
}

func (gpc GoogleProviderConfig) Validate() error {
	// TOOD: what can we validat here?
	return nil
}

type OktaProviderConfig struct {
	ServerID string `mapstructure:"server-id"`
	OrgURL   string `mapstructure:"org-url"`
}

func (opc OktaProviderConfig) Validate() error {
	if opc.OrgURL == "" {
		return xerrors.New("no okta.org-url is configured")
	}

	if opc.ServerID == "" {
		return xerrors.New("no okta.server-id is configured")
	}

	return nil
}

type GroupCacheConfig struct {
	ProviderTTL time.Duration `mapstructure:"provider-ttl"`
	RefreshTTL  time.Duration `mapstructure:"refresh-ttl"`
}

func (gcc GroupCacheConfig) Validate() error {
	return nil
}

type SessionConfig struct {
	CookieConfig       CookieConfig  `mapstructure:"cookie"`
	SessionLifetimeTTL time.Duration `mapstructure:"lifetime-ttl"`
	AuthCodeSecret     string        `mapstructure:"auth-secret"`
}

func (sc SessionConfig) Validate() error {
	// TODO: we can validate this secret is usable
	if sc.AuthCodeSecret == "" {
		return xerrors.New("no session.auth-secret configured")
	}

	if _, err := base64.StdEncoding.DecodeString(sc.AuthCodeSecret); err != nil {
		return xerrors.Errorf("invalid session.auth-secret: %w", err)
	}

	if sc.SessionLifetimeTTL >= (365*24)*time.Hour || sc.SessionLifetimeTTL <= 1*time.Minute {
		return xerrors.Errorf("session.lifetime-ttl must be between 1 minute and 1 year but is: %v", sc.SessionLifetimeTTL)
	}

	if err := sc.CookieConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid session.cookie config: %w", err)
	}

	return nil
}

type CookieConfig struct {
	Name     string        `mapstructure:"name"`
	Secret   string        `mapstructure:"secret"`
	Domain   string        `mapstructure:"domain"`
	Expire   time.Duration `mapstructure:"expire"`
	Secure   bool          `mapstructure:"secure"`
	HTTPOnly bool          `mapstructure:"http-only"`
}

func (cc CookieConfig) Validate() error {
	// TODO: Validate cookie secret:
	if cc.Name == "" {
		return xerrors.New("no cookie.name configured")
	}

	cookie := &http.Cookie{Name: cc.Name}
	if cookie.String() == "" {
		return xerrors.Errorf("invalid cookie.name: %q", cc.Name)
	}

	if cc.Secret == "" {
		return xerrors.New("no cookie.secret configured")
	}

	if _, err := base64.StdEncoding.DecodeString(cc.Secret); err != nil {
		return xerrors.Errorf("invalid cookie.secret: %w", err)
	}

	return nil
}

type ServerConfig struct {
	TCPConfig TCPConfig `mapstructure:"tcp"`

	Timeout time.Duration `mapstructure:"timeout"`
	Host    string        `mapstructure:"host"`
	Port    int           `mapstructure:"port"`
}

func (sc ServerConfig) Validate() error {
	if sc.Host == "" {
		return xerrors.New("no server.host configured")
	}

	if sc.Port == 0 {
		return xerrors.New("no server.port configured")
	}

	if err := sc.TCPConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid server.tcp config: %w", err)
	}

	return nil
}

type TCPConfig struct {
	WriteTimeout time.Duration `mapstructure:"write-timeout"`
	ReadTimeout  time.Duration `mapstructure:"read-timeout"`
}

func (tc TCPConfig) Validate() error {
	// TODO: any validation?
	return nil
}

type ClientConfig struct {
	ClientID     string `mapstructure:"id"`
	ClientSecret string `mapstructure:"secret"`
}

func (cc ClientConfig) Validate() error {
	if cc.ClientID == "" {
		return xerrors.New("no client.id configured")
	}

	if cc.ClientSecret == "" {
		return xerrors.New("no client.secret configured")
	}

	return nil
}

type AuthorizeConfig struct {
	EmailDomains     []string `mapstructure:"email-domains"`
	EmailAddresses   []string `mapstructure:"email-addresses"`
	ProxyRootDomains []string `mapstructure:"proxy-root-domains"`
}

func (ac AuthorizeConfig) Validate() error {
	if len(ac.ProxyRootDomains) == 0 {
		return xerrors.New("no authorize.proxy-root-domains configured")
	}

	if len(ac.EmailDomains) > 0 && len(ac.EmailAddresses) > 0 {
		return xerrors.New("can not specify both authorize.email-domains and authorize.email-addesses")
	}

	if len(ac.EmailDomains) == 0 && len(ac.EmailAddresses) == 0 {
		return xerrors.New("must specify either authorize.email-domains or authorize.email-addresses")
	}

	return nil
}

type MetricsConfig struct {
	RequestLogging bool         `mapstructure:"request-logging"`
	StatsdConfig   StatsdConfig `mapstructure:"statsd"`
}

func (mc MetricsConfig) Validate() error {
	if err := mc.StatsdConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid metrics.statsd config: %w", err)
	}

	return nil
}

type StatsdConfig struct {
	Port int    `mapstructure:"port"`
	Host string `mapstructure:"host"`
}

func (sc StatsdConfig) Validate() error {
	if sc.Host == "" {
		return xerrors.New("no statsd.host configured")
	}

	if sc.Port == 0 {
		return xerrors.New(" no statsd.port configured")
	}

	return nil
}

// LoadConfig loads all the configuration from env and defaults
func LoadConfig() (Configuration, error) {
	c := DefaultAuthConfig()

	conf := config.NewConfig()
	err := conf.Load(env.NewSource())
	if err != nil {
		return c, err
	}

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
		),
		Result: &c,
	})
	if err != nil {
		return c, err
	}

	decoder.Decode(conf.Map())

	return c, nil
}
