package acme

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"account": &framework.FieldSchema{
				Type:     framework.TypeString,
				Required: true,
			},
			"allowed_domains": &framework.FieldSchema{
				Type: framework.TypeCommaStringSlice,
			},
			"allow_bare_domains": &framework.FieldSchema{
				Type: framework.TypeBool,
			},
			"allow_subdomains": &framework.FieldSchema{
				Type: framework.TypeBool,
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

	r := role{
		Account:          data.Get("account").(string),
		AllowedDomains:   data.Get("allowed_domains").([]string),
		AllowBareDomains: data.Get("allow_bare_domains").(bool),
		AllowSubdomains:  data.Get("allow_subdomains").(bool),
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
		},
	}, nil
}

func (b *backend) roleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, req.Path)
}

type role struct {
	Account          string
	AllowedDomains   []string
	AllowBareDomains bool
	AllowSubdomains  bool
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
	storageEntry.DecodeJSON(&d)

	allowedDomains := make([]string, len(d["allowed_domains"].([]interface{})))
	for i, domain := range d["allowed_domains"].([]interface{}) {
		allowedDomains[i] = domain.(string)
	}

	return &role{
		Account:          d["account"].(string),
		AllowedDomains:   allowedDomains,
		AllowBareDomains: d["allow_bare_domains"].(bool),
		AllowSubdomains:  d["allow_subdomains"].(bool),
	}, nil
}

func (r *role) save(ctx context.Context, storage logical.Storage, path string) error {
	storageEntry, err := logical.StorageEntryJSON(path, map[string]interface{}{
		"account":            r.Account,
		"allowed_domains":    r.AllowedDomains,
		"allow_bare_domains": r.AllowBareDomains,
		"allow_subdomains":   r.AllowSubdomains,
	})

	if err != nil {
		return err
	}

	return storage.Put(ctx, storageEntry)
}
