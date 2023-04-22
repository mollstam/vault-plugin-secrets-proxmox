package proxmox

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
)

type proxmoxConfig struct {
	User               string        `json:"user"`
	Realm              string        `json:"realm"`
	ApiTokenID         string        `json:"token_id"`
	ApiTokenSecret     string        `json:"token_secret"`
	ApiURL             string        `json:"proxmox_url"`
	SkipCertValidation bool          `json:"insecure_skip_tls_verify"`
	HTTPHeaders        string        `json:"http_headers"`
	ProxyServer        string        `json:"proxy_server"`
	TaskTimeout        time.Duration `json:"timeout"`
}

func pathConfig(b *proxmoxBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"user": {
				Type:        framework.TypeString,
				Description: "User that configured API token is for, e.g. root",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "User",
				},
			},
			"realm": {
				Type:        framework.TypeString,
				Description: "Realm of the user that configured API token is for, e.g. pam",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Realm",
				},
			},
			"token_id": {
				Type:        framework.TypeString,
				Description: "API Token ID e.g. mytesttoken (excluding '<user>@<realm>!' which are set separately)",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "API Token ID",
					Sensitive: true,
				},
			},
			"token_secret": {
				Type:        framework.TypeString,
				Description: "The secret uuid corresponding to a TokenID",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "API Token Secret",
					Sensitive: true,
				},
			},
			"proxmox_url": {
				Type:        framework.TypeString,
				Description: "https://host.fqdn:8006/api2/json",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "API Endpoint URL",
				},
			},
			"insecure_skip_tls_verify": {
				Type:        framework.TypeBool,
				Description: "By default, every TLS connection is verified to be secure. This option allows Vault to proceed and operate on servers considered insecure. For example if you're connecting to a remote host and you do not have the CA cert that issued the proxmox api url's certificate.",
				Required:    false,
				Default:     false,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Skip TLS Verify",
				},
			},
			"http_headers": {
				Type:        framework.TypeString,
				Description: "Set custom http headers e.g. Key,Value,Key1,Value1",
				Required:    false,
				Default:     "",
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "HTTP Headers",
				},
			},
			"proxy_server": {
				Type:        framework.TypeString,
				Description: "Proxy Server passed to Api client(useful for debugging). Syntax: http://proxy:port",
				Required:    false,
				Default:     "",
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Proxy Server",
				},
			},
			"timeout": {
				Type:        framework.TypeInt,
				Description: "How many seconds to wait for operations for api-client, default is 2m",
				Required:    false,
				Default:     120,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Task Timeout",
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

func (b *proxmoxBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

func (b *proxmoxBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	c, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"user":                     c.User,
			"realm":                    c.Realm,
			"token_id":                 c.ApiTokenID,
			"proxmox_url":              c.ApiURL,
			"insecure_skip_tls_verify": c.SkipCertValidation,
			"http_headers":             c.HTTPHeaders,
			"proxy_server":             c.ProxyServer,
			"timeout":                  int(c.TaskTimeout.Seconds()),
		},
	}, nil
}

func (b *proxmoxBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := (req.Operation == logical.CreateOperation)

	if config == nil {
		if !createOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = new(proxmoxConfig)
	}

	if user, ok := data.GetOk("user"); ok {
		config.User = user.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing user in configuration")
	}

	if realm, ok := data.GetOk("realm"); ok {
		config.Realm = realm.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing realm in configuration")
	}

	if tokenID, ok := data.GetOk("token_id"); ok {
		config.ApiTokenID = tokenID.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing token_id in configuration")
	}

	if tokenSecret, ok := data.GetOk("token_secret"); ok {
		config.ApiTokenSecret = tokenSecret.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing token_secret in configuration")
	}

	apiURL, ok := data.GetOk("proxmox_url")
	ok = ok && len(apiURL.(string)) > 0
	if ok {
		config.ApiURL = apiURL.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing proxmox_url in configuration")
	}

	if skipCert, ok := data.GetOk("insecure_skip_tls_verify"); ok {
		config.SkipCertValidation = skipCert.(bool)
	} else if !ok && createOperation {
		config.SkipCertValidation = data.GetDefaultOrZero("insecure_skip_tls_verify").(bool)
	}

	if httpHeaders, ok := data.GetOk("http_headers"); ok {
		config.HTTPHeaders = httpHeaders.(string)
	} else if !ok && createOperation {
		config.HTTPHeaders = data.GetDefaultOrZero("http_headers").(string)
	}

	if proxyServer, ok := data.GetOk("proxy_server"); ok {
		config.ProxyServer = proxyServer.(string)
	} else if !ok && createOperation {
		config.ProxyServer = data.GetDefaultOrZero("proxy_server").(string)
	}

	if taskTimeout, ok := data.GetOk("timeout"); ok {
		config.TaskTimeout = time.Duration(taskTimeout.(int)) * time.Second
	} else if !ok && createOperation {
		config.TaskTimeout = time.Duration(data.GetDefaultOrZero("timeout").(int)) * time.Second
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

func (b *proxmoxBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
}

func getConfig(ctx context.Context, s logical.Storage) (*proxmoxConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(proxmoxConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configration: %w", err)
	}

	return config, nil
}

const pathConfigHelpSynopsis = `Configure the Proxmox backend.`

const pathConfigHelpDescription = `
The Proxmox secrets backend requires credentials for managing
API tokens using the Proxmox API.

You must sign in to your Proxmox cluster and create an API token and give that token to this secrets engine,
which will be used to mint new short lived tokens.`
