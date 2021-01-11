package acme

import (
	"context"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathSign(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex("role"),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathSign,
		},

		HelpSynopsis:    pathSignHelpSyn,
		HelpDescription: pathSignHelpDesc,
	}

	ret.Fields = addNonCACommonFields(map[string]*framework.FieldSchema{})

	ret.Fields["csr"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "",
		Description: `PEM-format CSR to be signed.`,
	}

	return ret
}

// pathSign issues a certificate from a submitted CSR, subject to role
// restrictions
func (b *backend) pathSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)

	// Get the role
	role, err := getRole(ctx, req.Storage, "roles/"+roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("unknown role: %s", roleName)), nil
	}

	return b.pathIssueSignCert(ctx, req, data, role)
}

func (b *backend) pathIssueSignCert(ctx context.Context, req *logical.Request, data *framework.FieldData, role *role) (*logical.Response, error) {

	format := getFormat(data)
	if format == "" {
		return logical.ErrorResponse(
			`the "format" path parameter must be "pem", "der", or "pem_bundle"`), nil
	}

	// input := &inputBundle{
	// 	req:     req,
	// 	apiData: data,
	// 	role:    role,
	// }
	// var parsedBundle *certutil.ParsedCertBundle
	// var err error
	parsedBundle, err := signCert(b, input, signingBundle, false, false)
	if err != nil {
		return nil, errwrap.Wrapf("error signing/generating certificate: {{err}}", err)
	}

	// signingCB, err := signingBundle.ToCertBundle()
	// if err != nil {
	// 	return nil, errwrap.Wrapf("error converting raw signing bundle to cert bundle: {{err}}", err)
	// }

	// cb, err := parsedBundle.ToCertBundle()
	// if err != nil {
	// 	return nil, errwrap.Wrapf("error converting raw cert bundle to cert bundle: {{err}}", err)
	// }

	respData := map[string]interface{}{
		// 	"expiration":    int64(parsedBundle.Certificate.NotAfter.Unix()),
		// 	"serial_number": cb.SerialNumber,
	}

	// switch format {
	// case "pem":
	// 	respData["issuing_ca"] = signingCB.Certificate
	// 	respData["certificate"] = cb.Certificate
	// 	if cb.CAChain != nil && len(cb.CAChain) > 0 {
	// 		respData["ca_chain"] = cb.CAChain
	// 	}

	// case "pem_bundle":
	// 	respData["issuing_ca"] = signingCB.Certificate
	// 	respData["certificate"] = cb.ToPEMBundle()
	// 	if cb.CAChain != nil && len(cb.CAChain) > 0 {
	// 		respData["ca_chain"] = cb.CAChain
	// 	}

	// case "der":
	// 	respData["certificate"] = base64.StdEncoding.EncodeToString(parsedBundle.CertificateBytes)
	// 	respData["issuing_ca"] = base64.StdEncoding.EncodeToString(signingBundle.CertificateBytes)

	// 	var caChain []string
	// 	for _, caCert := range parsedBundle.CAChain {
	// 		caChain = append(caChain, base64.StdEncoding.EncodeToString(caCert.Bytes))
	// 	}
	// 	if caChain != nil && len(caChain) > 0 {
	// 		respData["ca_chain"] = caChain
	// 	}
	// }

	// var resp *logical.Response
	// switch {
	// case role.GenerateLease == nil:
	// 	return nil, fmt.Errorf("generate lease in role is nil")
	// case *role.GenerateLease == false:
	// 	// If lease generation is disabled do not populate `Secret` field in
	// 	// the response
	// 	resp = &logical.Response{
	// 		Data: respData,
	// 	}
	// default:
	// 	resp = b.Secret(SecretCertsType).Response(
	// 		respData,
	// 		map[string]interface{}{
	// 			"serial_number": cb.SerialNumber,
	// 		})
	// 	resp.Secret.TTL = parsedBundle.Certificate.NotAfter.Sub(time.Now())
	// }

	// if data.Get("private_key_format").(string) == "pkcs8" {
	// 	err = convertRespToPKCS8(resp)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }

	// 	if role.UseCSRCommonName && data.Get("common_name").(string) != "" {
	// 		resp.AddWarning("the common_name field was provided but the role is set with \"use_csr_common_name\" set to true")
	// 	}
	// 	if role.UseCSRSANs && data.Get("alt_names").(string) != "" {
	// 		resp.AddWarning("the alt_names field was provided but the role is set with \"use_csr_sans\" set to true")
	// 	}

	// return resp, nil
	return nil, nil
}

const pathSignHelpSyn = `
Request certificates using a certain role with the provided details.
`

const pathSignHelpDesc = `
This path allows requesting certificates to be issued according to the
policy of the given role. The certificate will only be issued if the
requested common name is allowed by the role policy.
This path requires a CSR; if you want Vault to generate a private key
for you, use the issue path instead.
`
