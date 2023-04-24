package proxmox

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	pxapi "github.com/Telmate/proxmox-api-go/proxmox"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	envVarRunAccTests               = "VAULT_ACC"
	envVarProxmoxUser               = "VAULT_PROXMOX_USER"
	envVarProxmoxRealm              = "VAULT_PROXMOX_REALM"
	envVarProxmoxApiTokenID         = "VAULT_PROXMOX_API_TOKEN_ID"
	envVarProxmoxApiTokenSecret     = "VAULT_PROXMOX_API_TOKEN_SECRET"
	envVarProxmoxApiURL             = "VAULT_PROXMOX_API_URL"
	envVarProxmoxSkipCertValidation = "VAULT_PROXMOX_SKIP_CERT_VALIDATION"
	envVarProxmoxHTTPHeaders        = "VAULT_PROXMOX_HTTP_HEADERS"
	envVarProxmoxProxyServer        = "VAULT_PROXMOX_PROXY_SERVER"
	envVarProxmoxRoleUser           = "VAULT_PROXMOX_ROLE_USER"
	envVarProxmoxRoleRealm          = "VAULT_PROXMOX_ROLE_REALM"
)

var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

type testEnv struct {
	User               string
	Realm              string
	ApiTokenID         string
	ApiTokenSecret     string
	ApiURL             string
	SkipCertValidation bool
	HTTPHeaders        string
	ProxyServer        string

	RoleUser  string
	RoleRealm string

	Backend logical.Backend
	Context context.Context
	Storage logical.Storage

	SecretToken string

	Tokens []string
}

func newAcceptanceTestEnv() (*testEnv, error) {
	ctx := context.Background()

	maxLease, _ := time.ParseDuration("60s")
	defaultLease, _ := time.ParseDuration("30s")
	conf := &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLease,
			MaxLeaseTTLVal:     maxLease,
		},
		Logger: logging.NewVaultLogger(hclog.Debug),
	}
	b, err := Factory(ctx, conf)
	if err != nil {
		return nil, err
	}

	return &testEnv{
		User:               os.Getenv(envVarProxmoxUser),
		Realm:              os.Getenv(envVarProxmoxRealm),
		ApiTokenID:         os.Getenv(envVarProxmoxApiTokenID),
		ApiTokenSecret:     os.Getenv(envVarProxmoxApiTokenSecret),
		ApiURL:             os.Getenv(envVarProxmoxApiURL),
		SkipCertValidation: os.Getenv(envVarProxmoxSkipCertValidation) == "1",
		HTTPHeaders:        os.Getenv(envVarProxmoxHTTPHeaders),
		ProxyServer:        os.Getenv(envVarProxmoxProxyServer),
		RoleUser:           os.Getenv(envVarProxmoxRoleUser),
		RoleRealm:          os.Getenv(envVarProxmoxRoleRealm),
		Backend:            b,
		Context:            ctx,
		Storage:            &logical.InmemStorage{},
	}, nil
}

func TestAcceptanceApiToken(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	acceptanceTestEnv, err := newAcceptanceTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("add config", acceptanceTestEnv.AddConfig)
	t.Run("read config", acceptanceTestEnv.ReadConfig)
	t.Run("add API token role", acceptanceTestEnv.AddApiTokenRole)
	t.Run("read API token role", acceptanceTestEnv.ReadApiTokenRole)
	t.Run("read API token cred", acceptanceTestEnv.ReadApiToken)
	t.Run("read API token cred", acceptanceTestEnv.ReadApiToken)
	t.Run("cleanup service tokens", acceptanceTestEnv.CleanupApiTokens)
}

func (e *testEnv) AddConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"user":                     e.User,
			"realm":                    e.Realm,
			"token_id":                 e.ApiTokenID,
			"token_secret":             e.ApiTokenSecret,
			"proxmox_url":              e.ApiURL,
			"insecure_skip_tls_verify": e.SkipCertValidation,
			"http_headers":             e.HTTPHeaders,
			"proxy_server":             e.ProxyServer,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

func (e *testEnv) ReadConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
	require.NotNil(t, resp)

	if User, ok := resp.Data["user"]; ok {
		require.Equal(t, e.User, User)
	} else {
		require.Fail(t, "missing user in config response")
	}

	if Realm, ok := resp.Data["realm"]; ok {
		require.Equal(t, e.Realm, Realm)
	} else {
		require.Fail(t, "missing realm in config response")
	}

	if ApiTokenID, ok := resp.Data["token_id"]; ok {
		require.Equal(t, e.ApiTokenID, ApiTokenID)
	} else {
		require.Fail(t, "missing token_id in config response")
	}

	if ApiURL, ok := resp.Data["proxmox_url"]; ok {
		require.Equal(t, e.ApiURL, ApiURL)
	} else {
		require.Fail(t, "missing proxmox_url in config response")
	}
}

func (e *testEnv) AddApiTokenRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-service-token",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"user":  e.RoleUser,
			"realm": e.RoleRealm,
			"ttl":   300,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

func (e *testEnv) ReadApiTokenRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-service-token",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
	require.NotNil(t, resp)

	if roleUser, ok := resp.Data["user"]; ok {
		require.Equal(t, e.RoleUser, roleUser)
	} else {
		require.Fail(t, "missing user in role response")
	}

	if roleRealm, ok := resp.Data["realm"]; ok {
		require.Equal(t, e.RoleRealm, roleRealm)
	} else {
		require.Fail(t, "missing realm in role response")
	}
}

func (e *testEnv) ReadApiToken(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-service-token",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
	require.NotNil(t, resp)

	if to, ok := resp.Data["token_id"]; ok {
		e.Tokens = append(e.Tokens, to.(string))
	}
	require.NotEmpty(t, resp.Data["token_id"])

	if e.SecretToken != "" {
		require.NotEqual(t, e.SecretToken, resp.Data["token_id"])
	}

	if fto, ok := resp.Data["token_id_full"]; ok {
		require.Equal(t, fmt.Sprintf("%s@%s!%s", e.RoleUser, e.RoleRealm, resp.Data["token_id"].(string)), fto)
	} else {
		require.Fail(t, "missing full token id in creds response")
	}

	// collect secret IDs to revoke at end of test
	require.NotNil(t, resp.Secret)
	if t, ok := resp.Secret.InternalData["token_id"]; ok {
		e.SecretToken = t.(string)
	}
}

func (e *testEnv) CleanupApiTokens(t *testing.T) {
	if len(e.Tokens) == 0 {
		t.Fatalf("expected 2 tokens, got: %d", len(e.Tokens))
	}

	for _, token := range e.Tokens {
		b := e.Backend.(*proxmoxBackend)
		c, err := b.getClient(e.Context, e.Storage)
		if err != nil {
			t.Fatal("fatal getting client")
		}

		u, err := pxapi.NewConfigUserFromApi(pxapi.UserID{Name: e.RoleUser, Realm: e.RoleRealm}, c.Client)
		if err != nil {
			t.Fatalf("unexpected error creating ConfigUser to delete token: %s", err)
		}

		u.DeleteApiToken(c.Client, pxapi.ApiToken{TokenId: token})
	}
}
