package config

import "time"

// config file
type (
	Backend struct {
		BaseDN                    string
		Datastore                 string
		Insecure                  bool     // For LDAP and owncloud backend only
		Servers                   []string // For LDAP and owncloud backend only
		NameFormat                string   // e.g. cn, ou, uid, or a comma separated list of them
		NameFormatAsArray         []string // we will explode NameFormat on commas
		GroupFormat               string   // e.g. cn, ou, gid, or a comma separated list of them
		GroupFormatAsArray        []string // we will explode GroupFormat on commas
		SSHKeyAttr                string
		UseGraphAPI               bool     // For ownCloud backend only
		Plugin                    string   // Path to plugin library, for plugin backend only
		PluginHandler             string   // Name of plugin's main handler function
		Database                  string   // For Database backends only
		GroupWithSearchCapability string   // For unix and pam backends only
		UnixFilesDir              string   // For unix and pam backends only: directory holding passwd, shadow and group (default /etc)
		MinUIDNumber              int      // For unix and pam backends only: hide accounts with a lower uid, unless they are in ExposeGroups or GroupWithSearchCapability
		ExposeGroups              []string // For unix and pam backends only: members of these groups are shown regardless of MinUIDNumber
		AnonymousDSE              bool     // For Config and Database backends only
	}

	Helper struct {
		Enabled       bool
		BaseDN        string
		Datastore     string
		Plugin        string // Path to plugin library, for plugin backend only
		PluginHandler string // Name of plugin's main handler function
		Database      string // For MySQL backend only TODO REname to match plugin
	}

	Frontend struct {
		AllowedBaseDNs []string // For LDAP backend only
		Listen         string
		Cert           string
		Key            string
		TLS            bool
	}

	LDAP struct {
		Enabled bool
		Listen  string
		// StartTLS parameters
		TLS         bool
		TLSCert     string
		TLSKey      string
		TLSCertPath string
		TLSKeyPath  string
		LegacyTLS   bool
	}

	LDAPS struct {
		Enabled bool
		Listen  string
		// LDAPS TLS parameters
		Cert      string
		Key       string
		CertPath  string
		KeyPath   string
		LegacyTLS bool
	}

	API struct {
		Cert        string
		Enabled     bool
		Internals   bool
		Key         string
		Listen      string
		SecretToken string
		TLS         bool
	}

	Behaviors struct {
		IgnoreCapabilities    bool
		LimitFailedBinds      bool
		NumberOfFailedBinds   int
		PeriodOfFailedBinds   time.Duration
		BlockFailedBindsFor   time.Duration
		PruneSourceTableEvery time.Duration
		PruneSourcesOlderThan time.Duration
		LegacyVersion         int
	}

	Capability struct {
		Action string
		Object string
	}

	// UserAuthenticator authenticates a user via custom auth from a backend
	UserAuthenticator func(user *User, pw string) error
	User              struct {
		Name          string
		OtherGroups   []int
		PassSHA256    string
		PassBcrypt    string
		PassAppSHA256 []string
		PassAppBcrypt []string
		PassAppCustom UserAuthenticator `toml:"-"`
		PrimaryGroup  int
		Capabilities  []Capability
		SSHKeys       []string
		OTPSecret     string
		Yubikey       string
		Disabled      bool
		UnixID        int // TODO: remove after deprecating UnixID on User and Group
		UIDNumber     int
		Mail          string
		LoginShell    string
		GivenName     string
		SN            string
		Homedir       string
		CustomAttrs   map[string]interface{}
	}

	Group struct {
		Name          string
		UnixID        int // TODO: remove after deprecating UnixID on User and Group
		GIDNumber     int
		Capabilities  []Capability
		IncludeGroups []int
	}

	// OIDC configures the OpenID Connect provider. Applications served from hosts under
	// Domain can sign users in without being registered: the client ID is the
	// application's host name, and tokens are only ever sent back to that host.
	OIDC struct {
		Enabled     bool
		Domain      string // the domain we serve; the issuer defaults to https://auth.<Domain>
		Issuer      string // public URL of the provider, if not https://auth.<Domain>
		Listen      string // HTTP listen address, usually behind a reverse proxy (default 0.0.0.0:8080)
		TLSCertPath string // serve HTTPS directly with this certificate and key
		TLSKeyPath  string
		// LDAP server to check passwords against, as ldap://host:port or ldaps://host:port.
		// Defaults to this process's own LDAP listener.
		LDAP          string
		LDAPInsecure  bool   // skip certificate verification for ldaps://
		BaseDN        string // defaults to the first backend's BaseDN
		NameAttribute string // attribute naming users in bind DNs; defaults to the first backend's name format
		// BindFormat is what users bind to LDAP as, with {username} and {baseDN}
		// in it, as {username}@example.com for Active Directory; by default
		// <NameAttribute>={username},{baseDN}.
		BindFormat string
		// UserFilter finds the signing-in user's entry, with {username} in it, as
		// (&(objectClass=user)(sAMAccountName={username})) for Active Directory; by
		// default (&(objectClass=posixAccount)(<NameAttribute>={username})).
		UserFilter string
		StateDir   string // where signing keys are kept; keys are regenerated on every start if empty
		// ClientSecrets says how secrets from applications that aren't listed in Clients are
		// checked: "ignore" (the default) accepts any secret, "derived" requires the
		// secret printed by "glauth oidc-secret <client-id>".
		ClientSecrets   string
		TrustedDomains  []string      // further domains whose hosts may sign users in; Domain is always trusted
		SessionLifetime time.Duration // how long a sign-in lasts before the password is asked again (default 12h)
		Clients         []OIDCClient
		Branding        OIDCBranding
		// AdminGroups may manage the provider at https://auth.<Domain>/admin: change
		// settings, see and end sessions, and block applications.
		AdminGroups []string
		// AdminReauthAfter is how recently admins must have given their password to use
		// the admin page, as a duration such as "15m" (the default), or "never" to accept
		// any session.
		AdminReauthAfter string
		// AdminFile holds the settings changed on the admin page (default <StateDir>/oidc-admin.toml).
		AdminFile string
	}

	// OIDCClient is an application with settings of its own: one outside the trusted
	// domains, one that should only admit some groups, or one with a fixed secret.
	OIDCClient struct {
		ID           string
		Name         string   // shown on the sign-in page
		Secret       string   // if set, the application must present it
		RedirectURIs []string // patterns, where ** matches any path
		Groups       []string // if set, only members of these groups may sign in
	}

	// OIDCBranding customises the sign-in pages.
	OIDCBranding struct {
		Name      string // shown as the page title (default: the domain)
		Logo      string // path to an image file shown above the form
		CSS       string // path to a stylesheet loaded after the built-in one
		Templates string // directory of templates replacing the built-in ones
	}

	Tracing struct {
		Enabled      bool
		GRPCEndpoint string
		HTTPEndpoint string
	}

	Config struct {
		API                API
		Backend            Backend // Deprecated
		Backends           []Backend
		Helper             Helper
		Behaviors          Behaviors
		Debug              bool
		Syslog             bool
		StructuredLog      bool
		WatchConfig        bool
		YubikeyClientID    string
		YubikeySecret      string
		Frontend           Frontend
		LDAP               LDAP
		LDAPS              LDAPS
		OIDC               OIDC
		Groups             []Group
		Users              []User
		Tracing            Tracing
		ConfigFile         string
		AwsAccessKeyId     string
		AwsSecretAccessKey string
		AwsRegion          string
	}
)
