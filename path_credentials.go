package proxmox

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCredentials(b *proxmoxBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathCredentialsRead,
			logical.UpdateOperation: b.pathCredentialsRead,
		},
		HelpSynopsis:    pathCredentialsHelpSyn,
		HelpDescription: pathCredentialsHelpDesc,
	}
}

func (b *proxmoxBackend) createToken(ctx context.Context, s logical.Storage, role *proxmoxRoleEntry) (*proxmoxToken, error) {
	client, err := b.getClient(ctx, s)
	if err != nil {
		return nil, err
	}

	var token *proxmoxToken

	expire := int64(0)
	if role.TTL > 0 {
		expire = time.Now().Add(role.TTL).Unix()
	}

	// TODO: separated privileges always false for now, should support setting what privileges to use before exposing?
	privsep := false

	token, err = createToken(ctx, client, role.User, role.Realm, expire, privsep)
	if err != nil {
		return nil, fmt.Errorf("error creating Proxmox API token for role '%v': %w", role.Name, err)
	}

	if token == nil {
		return nil, errors.New("error creating Proxmox API token")
	}

	return token, nil
}

func (b *proxmoxBackend) createUserCreds(ctx context.Context, req *logical.Request, role *proxmoxRoleEntry) (*logical.Response, error) {
	token, err := b.createToken(ctx, req.Storage, role)
	if err != nil {
		return nil, err
	}

	tokenIDFull := fmt.Sprintf("%s@%s!%s", role.User, role.Realm, token.TokenID)

	resp := b.Secret(proxmoxTokenType).Response(map[string]interface{}{
		"token_id":      token.TokenID,
		"token_id_full": tokenIDFull,
		"secret":        token.Secret,
	}, map[string]interface{}{
		"token_id": token.TokenID,
		"role":     role.Name,
	})

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}

func (b *proxmoxBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	return b.createUserCreds(ctx, req, roleEntry)
}

const pathCredentialsHelpSyn = `
Generate a Proxmox API token from a specific Vault role.
`

const pathCredentialsHelpDesc = `
This path generates a Proxmox API token based on a particular role.
`
