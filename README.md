# Vault Plugin: Proxmox

This is a standalone backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This plugin provides handling of Proxmox VE API tokens by Vault.

This plugin is a bit "first pass" and can not yet create tokens with privileges separate from the user account it belongs to (pull requests welcome :sparkles:).

## Getting Started

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html)
and is meant to work with Vault. This guide assumes you have already installed Vault
and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with Vault](https://www.vaultproject.io/intro/getting-started/install.html).

To learn specifically about how plugins work, see documentation on [Vault plugins](https://www.vaultproject.io/docs/internals/plugins.html).

## Installation

Currently no built release is distributed, you'll have to build from source for your chosen OS and architecture.

1. Clone this repository and change directory into the root.
2. For good measure, run some tests: `go test -v`.
3. Change directory into `cmd/vault-plugin-secrets-proxmox`
4. Build the plugin `go build` and then get the SHA256 hash of the binary.
5. Install the plugin and register it with the hash, see the [Vault plugin docs](https://developer.hashicorp.com/vault/docs/plugins/plugin-architecture#plugin-registration) for more information.

## Setup (Proxmox)

1. Access your Proxmox VE cluster and under **Permissions** / **API Tokens** create a new API token that you will setup the Vault secrets engine with.
2. If you want the role(s), and subsequent minted API tokens, to impersonate a user other than you (probably a good idea) create those accounts under **Permissions** / **Users** (eg `ci` or `packer` or I don't know..). The minted tokens will inherit **all** permissions of the user their role is created for, until we've added support for separate per-token privileges.

## Setup (Vault)

1. With the plugin installed from the steps above, mount it at some endpoint of your choosing
```sh
vault secrets enable -path=proxmox vault-plugin-secrets-proxmox
```

2. Configure the plugin
```sh
vault write proxmox/config user=<User that configured API token is for, e.g. root> realm=<Realm of the user that configured API token is for, e.g. pam> token_id=<API Token ID e.g. mytesttoken (excluding '<user>@<realm>!' which are set separately)> token_secret=<The secret uuid corresponding to a TokenID> proxmox_url=<API Endpoint URL, e.g. https://host.fqdn:8006/api2/json>
```
Optional config fields include `insecure_skip_tls_verify`, `http_headers`, `proxy_server` and `timeout`.

3. Create a role for the Proxmox user you are going to create tokens for
```sh
vault write proxmox/role/alice user="alice" realm="pve"
```

4. To test that it works, retrieve a new Proxmox API token from Vault
```sh
vault read proxmox/creds/alice
```

5. You should now have gotten an API token for Proxmox, now lets revoke it (using the output `lease_id`)
```sh
vault lease revoke proxmox/creds/alice/<lease id>
```

## Contribute

Pull requests welcome, and be nice.
