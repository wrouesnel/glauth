
# GLAuth: LDAP authentication server for developers
[![Official GLAuth Website](https://img.shields.io/badge/Official%20GLAuth%20Website-glauth.github.io-brightgreen?style=plastic)](https://glauth.github.io/)
[![kittens dns](https://img.shields.io/badge/kittens%20dns-github-blue?style=plastic)](https://github.com/fusion/kittendns)
[![wing vpn](https://img.shields.io/badge/wing%20vpn-github-orange?style=plastic)](https://github.com/fusion/wing-vpn)

Go-lang LDAP Authentication (GLAuth) is a secure, easy-to-use, LDAP server w/ configurable backends.

![GitHub all releases](https://img.shields.io/github/downloads/glauth/glauth/total)
![Docker pulls](https://badgen.net/docker/pulls/glauth/glauth)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/glauth/glauth/master)

* Centrally manage accounts across your infrastructure
* Centrally manage SSH keys, Linux accounts, and passwords for cloud servers.
* Lightweight alternative to OpenLDAP and Active Directory for development, or a homelab.
* Store your user directory in a file, local or in S3; SQL database; or proxy to existing LDAP servers.
* Two Factor Authentication (transparent to applications)
* Multiple backends can be chained to inject features

Use it to centralize account management across your Linux servers, your OSX machines, and your support applications (Jenkins, Apache/Nginx, Graylog2, and many more!).

### About this fork
This is a fork inspired by [glauth/glauth](https://github.com/glauth/glauth), developed as its own software rather than to contribute back upstream. It differs in that:

- Every backend is compiled into one binary, with no cgo: `config`, `ldap`, `owncloud`, `sqlite`, `mysql`, `postgres` and `unix`. `unix` serves the host's `passwd`, `shadow` and `group` and checks passwords against `shadow` itself. The `pam` backend needs cgo, so it's only built with `GO_BUILD_TAGS=pam`.
- It is built with [mage](https://magefile.org): `go run mage.go binary` builds `./glauth`, and `go run mage.go -l` lists the other targets (`test`, `lint`, `style`, `releaseAll`, …). The container image is `ghcr.io/wrouesnel/glauth`.
- Releases are tagged `wrouesnel-v<semver>`, and its versions carry a `+wrouesnel` marker, e.g. `v2.6.0+wrouesnel`.
- It is also an OpenID Connect provider, so applications that don't speak LDAP can sign users in against the same accounts. See below.

### OpenID Connect

glauth can sign users in to applications with OpenID Connect, checking passwords against its own LDAP server. It is meant for a domain you control, served at `https://auth.<domain>`.

Applications under the domain don't need registering. To connect one, give it:

- **Issuer:** `https://auth.example.com`. The application finds every endpoint from there.
- **Client ID:** the application's own host name, such as `grafana.example.com`. Tokens are only ever sent back to that host, over HTTPS, on any path or port.
- **Client secret:** anything, unless `clientSecrets = "derived"` (see below).
- **Scopes:** `openid profile email groups`. Add `offline_access` if the application wants refresh tokens.

Tokens and userinfo carry `sub` and `preferred_username` (the user name), `name`, `given_name`, `family_name`, `email` (marked verified) and `groups`, which lists the user's group names. Most applications can map an admin role from `groups`.

Signing in to one application signs the browser in to all of them for `sessionLifetime` (12 hours by default). `https://auth.<domain>/logout` signs it out.

```toml
[oidc]
  enabled = true
  domain = "example.com"           # issuer https://auth.example.com; apps on *.example.com are trusted
  listen = "0.0.0.0:8080"          # plain HTTP, for a reverse proxy that terminates TLS
  stateDir = "/var/lib/glauth"     # keeps the signing keys across restarts
  # trustedDomains = ["lab.example.org"]
  # adminGroups = ["admins"]       # may manage the provider at https://auth.example.com/admin
  # clientSecrets = "derived"      # apps must use the secret from: glauth -c <config> --oidc-secret <client-id>
  [oidc.branding]
    name = "Example"               # shown on the sign-in page
    # logo = "/config/logo.svg"
    # css = "/config/auth.css"     # loaded after the built-in stylesheet
    # templates = "/config/templates"  # replaces layout.html, login.html or message.html (see v2/pkg/idp/ui)

# Applications outside the trusted domains, or with rules of their own:
[[oidc.clients]]
  id = "grafana.example.com"
  groups = ["admins"]              # only these groups may sign in
  # secret = "..."                 # require this secret
  # redirectURIs = ["https://grafana.example.com/login/generic_oauth"]  # ** matches any path
```

The provider binds to LDAP as the user who is signing in and reads their own entry, so it needs no service account. By default it uses the same process's LDAP listener. To run it separately, for example without access to `/etc/shadow`, give a second glauth a config with only an `[oidc]` section, `[ldaps] enabled = false`, and `ldap = "ldap://ldap-host:3893"` and `baseDN` set. See `v2/sample-oidc.cfg`.

#### Administration

With `adminGroups = ["admins"]` in `[oidc]`, members of those groups can manage the provider at `https://auth.<domain>/admin`. They can:

- see who is signed in, from where, and to which applications, and end a session, or all of a user's sessions. This also revokes the tokens issued through them.
- block an application for an hour, a day, a week or until unblocked, with a reason shown to users. Blocking also revokes its tokens.
- add applications: limit one to some groups, give it a secret (shown once, then stored hashed), or allow callback URLs outside its own host.
- change the name on the sign-in page, the session lifetime and the extra trusted domains.

The admin pages ask for the password again if it was last given more than 15 minutes ago, so an unattended signed-in browser can't be used to change anything. Giving it renews the browser's session.

Sessions and tokens are kept in `<stateDir>/oidc-state.db`, so a restart doesn't sign anyone out. Session cookies and refresh tokens are only stored hashed. Without a `stateDir`, everything is kept in memory and lost on restart.

Changes are saved to `adminFile` (default `<stateDir>/oidc-admin.toml`), which is applied over the `[oidc]` section of the main config. The main config is never rewritten, so it can stay hand-written or managed by tools like Ansible. Hand edits to the admin file are picked up within a minute. Applications set up in the main config are shown, but can only be changed there.

Limitation for now:

- Five wrong passwords for a user name within five minutes block that name for the rest of the five minutes. glauth's own `limitFailedBinds` counts failures by address, and every sign-in comes from the provider's address, so with OIDC in use, leave it off.

### Contributing
- Please base all Pull Requests on [dev](https://github.com/glauth/glauth/tree/dev), not master.
- Format your code automatically using `gofmt -d ./` before committing

### Quickstart
This quickstart is a great way to try out GLAuth in a non-production environment.  *Be warned that you should take the extra steps to setup SSL (TLS) for production use!*

1. Download a precompiled binary from the [releases](https://github.com/glauth/glauth/releases) page.
2. Download the [example config file](https://github.com/glauth/glauth/blob/master/v2/sample-simple.cfg).
3. Start the GLAuth server, referencing the path to the desired config file with `-c`.
   - `./glauth64 -c sample-simple.cfg`
4. Test with traditional LDAP tools
   - For example: `ldapsearch -LLL -H ldap://localhost:3893 -D cn=serviceuser,ou=svcaccts,dc=glauth,dc=com -w mysecret -x -bdc=glauth,dc=com cn=hackers`

### Make Commands

Note - makefile uses git data to inject build-time variables. For best results, run in the context of the git repo.

### Documentation

<h4 align="center">:point_right: The latest version of GLauth's documentation is available at https://glauth.github.io/ :point_left:</h4>

<hr>

### Quickstart

Get started in three short [steps](https://glauth.github.io/docs/quickstart.html)

### Usage:
```
glauth: securely expose your LDAP for external auth

Usage:
  glauth [options] -c <file|s3url>
  glauth -h --help
  glauth --version

Options:
  -c, --config <file>       Config file.
  -K <aws_key_id>           AWS Key ID.
  -S <aws_secret_key>       AWS Secret Key.
  -r <aws_region>           AWS Region [default: us-east-1].
  --ldap <address>          Listen address for the LDAP server.
  --ldaps <address>         Listen address for the LDAPS server.
  --ldaps-cert <cert-file>  Path to cert file for the LDAPS server.
  --ldaps-key <key-file>    Path to key file for the LDAPS server.
  --check-config            Check configuration file and exit.
  --oidc-secret <client-id> Print the secret an OIDC application must use when
                            oidc.clientSecrets is "derived", and exit.
  -h, --help                Show this screen.
  --version                 Show version.
```

### Configuration:
GLAuth can be deployed as a single server using only a local configuration file.  This is great for testing, or for production if you use a tool like Puppet/Chef/Ansible:
```unix
glauth -c glauth.cfg
```
Here's a sample config wth hardcoded users and groups:
```toml
[backend]
  datastore = "config"
  baseDN = "dc=glauth,dc=com"
[[users]]
  name = "hackers"
  uidnumber = 5001
  primarygroup = 5501
  passsha256 = "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a"   # dogood
  sshkeys = [ "ssh-dss AAAAB3..." ]
[[users]]
  name = "uberhackers"
  uidnumber = 5006
  primarygroup = 5501
  passbcrypt = "243261243130244B62463462656F7265504F762E794F324957746D656541326B4B46596275674A79336A476845764B616D65446169784E41384F4432"   # dogood
[[groups]]
  name = "superheros"
  gidnumber = 5501
```

More configuration options are documented [here](https://glauth.github.io/docs/file.html) and in this [sample file](https://github.com/glauth/glauth/blob/master/v2/sample-simple.cfg)

### Backends:

For advanced users, GLAuth supports pluggable backends.  Currently, it can use a local file, S3 or an existing LDAP infrastructure.  Through the use of optional plugins, you can connect SQL databases, PAM, and other datastores.

```toml
[backend]
  datastore = "ldap"
  servers = [ "ldaps://server1:636", "ldaps://server2:636" ]
```

# Stargazers over time

[![Stargazers over time](https://starchart.cc/glauth/glauth.svg)](https://starchart.cc/glauth/glauth)
