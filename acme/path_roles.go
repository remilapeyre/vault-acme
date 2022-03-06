package acme

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

func pathListRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.roleList,
		},
	}
}

func pathRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"account": {
				Type:     framework.TypeString,
				Required: true,
			},
			"allowed_domains": {
				Type: framework.TypeCommaStringSlice,
			},
			"allow_bare_domains": {
				Type: framework.TypeBool,
			},
			"allow_subdomains": {
				Type: framework.TypeBool,
			},
			"disable_cache": {
				Type: framework.TypeBool,
			},
			"cache_for_ratio": {
				Type:    framework.TypeInt,
				Default: 70,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.roleCreateOrUpdate,
			logical.ReadOperation:   b.roleRead,
			logical.UpdateOperation: b.roleCreateOrUpdate,
			logical.DeleteOperation: b.roleDelete,
		},
	}
}

func (b *backend) roleCreateOrUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := data.Validate(); err != nil {
		return nil, err
	}

	cacheForRatio := data.Get("cache_for_ratio").(int)
	if cacheForRatio <= 0 || cacheForRatio > 100 {
		return logical.ErrorResponse("cache_for_ration should be greater than 0 and less than 100"), nil
	}

	r := role{
		Account:          data.Get("account").(string),
		AllowedDomains:   data.Get("allowed_domains").([]string),
		AllowBareDomains: data.Get("allow_bare_domains").(bool),
		AllowSubdomains:  data.Get("allow_subdomains").(bool),
		DisableCache:     data.Get("disable_cache").(bool),
		CacheForRatio:    cacheForRatio,
	}
	if err := r.save(ctx, req.Storage, req.Path); err != nil {
		return nil, err
	}

	return b.roleRead(ctx, req, data)
}

func (b *backend) roleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	r, err := getRole(ctx, req.Storage, req.Path)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return logical.ErrorResponse("This role does not exists"), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"account":            r.Account,
			"allowed_domains":    r.AllowedDomains,
			"allow_bare_domains": r.AllowBareDomains,
			"allow_subdomains":   r.AllowSubdomains,
			"disable_cache":      r.DisableCache,
			"cache_for_ratio":    r.CacheForRatio,
		},
	}, nil
}

func (b *backend) roleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, req.Path)
}

func (b *backend) roleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

type role struct {
	Account          string
	AllowedDomains   []string
	AllowBareDomains bool
	AllowSubdomains  bool
	DisableCache     bool
	CacheForRatio    int
}

func getRole(ctx context.Context, storage logical.Storage, path string) (*role, error) {
	storageEntry, err := storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if storageEntry == nil {
		return nil, nil
	}

	var d map[string]interface{}
	err = storageEntry.DecodeJSON(&d)
	if err != nil {
		return nil, err
	}

	var r *role
	err = mapstructure.Decode(d, &r)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (r *role) save(ctx context.Context, storage logical.Storage, path string) error {
	var data map[string]interface{}
	err := mapstructure.Decode(r, &data)
	if err != nil {
		return err
	}

	storageEntry, err := logical.StorageEntryJSON(path, data)
	if err != nil {
		return err
	}

	return storage.Put(ctx, storageEntry)
}
