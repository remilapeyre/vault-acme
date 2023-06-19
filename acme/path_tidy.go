package acme

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

var tidyCancelledError = errors.New("tidy operation cancelled")

var operationPrefixACME = "acme"

type tidyStatusState int

const (
	tidyStatusInactive   tidyStatusState = iota
	tidyStatusStarted                    = iota
	tidyStatusFinished                   = iota
	tidyStatusError                      = iota
	tidyStatusCancelling                 = iota
	tidyStatusCancelled                  = iota
)

type tidyStatus struct {
	// Status
	state        tidyStatusState
	err          error
	timeStarted  time.Time
	timeFinished time.Time
	message      string
}

func pathTidy(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "tidy$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixACME,
			OperationVerb:   "tidy",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathTidyWrite,
				Responses: map[int][]framework.Response{
					http.StatusAccepted: {{
						Description: "Accepted",
						Fields:      map[string]*framework.FieldSchema{},
					}},
				},
				ForwardPerformanceStandby: true,
			},
		},
		HelpSynopsis:    pathTidyHelpSyn,
		HelpDescription: pathTidyHelpDesc,
	}
}

func (b *backend) tidyStatusMessage(msg string) {
	b.tidyStatusLock.Lock()
	defer b.tidyStatusLock.Unlock()

	b.tidyStatus.message = msg
}

func (b *backend) tidyStatusStart() {
	b.tidyStatusLock.Lock()
	defer b.tidyStatusLock.Unlock()
	// TODO:
	// 1. add tidy status and update it as we are going
	// 2. add an endpoint to view the tidy status for testing
	// 3. test

	b.tidyStatus = &tidyStatus{
		state:       tidyStatusStarted,
		timeStarted: time.Now(),
	}
}

func (b *backend) tidyStatusStop(err error) {
	b.tidyStatusLock.Lock()
	defer b.tidyStatusLock.Unlock()

	b.tidyStatus.timeFinished = time.Now()
	b.tidyStatus.err = err
	switch err {
	case nil:
		b.tidyStatus.state = tidyStatusFinished
	case tidyCancelledError:
		b.tidyStatus.state = tidyStatusCancelled
	default:
		b.tidyStatus.state = tidyStatusError
	}
}

func (b *backend) pathTidyCancelWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if atomic.LoadUint32(b.tidyCASGuard) == 0 {
		resp := &logical.Response{}
		resp.AddWarning("Tidy operation cannot be cancelled as none is currently running.")
		return resp, nil
	}

	// Grab the status lock before writing the cancel atomic. This lets us
	// update the status correctly as well, avoiding writing it if we're not
	// presently running.
	//
	// Unlock needs to occur prior to calling read.
	b.tidyStatusLock.Lock()
	if b.tidyStatus.state == tidyStatusStarted || atomic.LoadUint32(b.tidyCASGuard) == 1 {
		if atomic.CompareAndSwapUint32(b.tidyCancelCAS, 0, 1) {
			b.tidyStatus.state = tidyStatusCancelling
		}
	}
	b.tidyStatusLock.Unlock()

	return b.pathTidyStatusRead(ctx, req, d)
}

func (b *backend) pathTidyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if !atomic.CompareAndSwapUint32(b.tidyCASGuard, 0, 1) {
		resp := &logical.Response{}
		resp.AddWarning("Tidy operation already in progress.")
		return resp, nil
	}

	// Tests using framework will screw up the storage so make a locally
	// scoped req to hold a reference
	req = &logical.Request{
		Storage: req.Storage,
	}

	// Mark the last tidy operation as relatively recent, to ensure we don't
	// try to trigger the periodic function.
	b.tidyStatusLock.Lock()
	b.lastTidy = time.Now()
	b.tidyStatusLock.Unlock()

	// Kick off the actual tidy.
	b.startTidyOperation(req)

	resp := &logical.Response{}
	resp.AddWarning("Tidy operation successfully started. Any information from the operation will be printed to Vault's server logs.")

	return logical.RespondWithStatusCode(resp, req, http.StatusAccepted)
}

// TODO: run inside of a goroutine
// https://github.com/hashicorp/vault/blob/659316cff1e5a437a47447492a2a426c8222354b/builtin/logical/pki/backend.go#L443-L492
// Deletes / revokes certificate entries that don't have any users
func (b *backend) startTidyOperation(req *logical.Request) {
	go func() {
		atomic.StoreUint32(b.tidyCancelCAS, 0)
		defer atomic.StoreUint32(b.tidyCASGuard, 0)

		b.tidyStatusStart()

		// Don't cancel when the original client request goes away.
		ctx := context.Background()

		logger := b.Logger().Named("acme-tidy")

		doTidy := func() error {
			b.cache.Lock()

			keys, err := b.cache.List(ctx, req.Storage)
			if err != nil {
				return fmt.Errorf("failed to list cache: %w", err)
			}

			var keyErrors error
			for i, key := range keys {
				b.tidyStatusMessage(fmt.Sprintf("Tidying revoked certificates: checking certificate %d of %d", i, len(keys)))

				// Check for cancel before continuing.
				if atomic.CompareAndSwapUint32(b.tidyCancelCAS, 1, 0) {
					return tidyCancelledError
				}

				ceKey := cachePrefix + key
				ce, err := b.cache.GetCacheEntry(ctx, req.Storage, ceKey)
				if err != nil {
					keyErrors = multierror.Append(fmt.Errorf("failed to tidy %s: %w", ceKey, err))
					continue
				}

				if ce.Users > 0 {
					b.Logger().Debug("certificate has active users. skipping...", "certificateName", ceKey, "users", ce.Users)
					continue
				}

				a, err := getAccount(ctx, req.Storage, accountsPrefix+ce.Account)
				if err != nil {
					keyErrors = multierror.Append(fmt.Errorf("failed to tidy %s: failed to get account %s: %w", ceKey, ce.Account, err))
					continue
				}
				if a == nil {
					keyErrors = multierror.Append(fmt.Errorf("failed to tidy %s: account %s not found", ceKey, ce.Account))
					continue
				}
				client, err := a.getClient()
				if err != nil {
					keyErrors = multierror.Append(fmt.Errorf("failed to tidy %s: failed to get lego client: %w", ceKey, err))
					continue
				}

				err = b.cache.Delete(ctx, req.Storage, ceKey)
				if err != nil {
					keyErrors = multierror.Append(fmt.Errorf("failed to tidy %s: failed to delete cache entry: %w", ceKey, err))
					continue
				}

				err = client.Certificate.Revoke(ce.Cert)
				if err != nil {
					keyErrors = multierror.Append(fmt.Errorf("failed to tidy %s: failed to revoke the certificate: %w", ceKey, err))
					continue
				}
			}

			if keyErrors != nil {
				b.Logger().Error("failed to tidy keys", "errors", keyErrors)
				return fmt.Errorf("failed to tidy keys: %w", keyErrors)
			}

			return nil
		}

		if err := doTidy(); err != nil {
			logger.Error("error running tidy", "error", err)
			b.tidyStatusStop(err)
		} else {
			b.tidyStatusStop(nil)

			// Since the tidy operation finished without an error, we don't
			// really want to start another tidy right away (if the interval
			// is too short). So mark the last tidy as now.
			b.tidyStatusLock.Lock()
			b.lastTidy = time.Now()
			b.tidyStatusLock.Unlock()
		}

	}()
}

func (b *backend) pathTidyStatusRead(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.tidyStatusLock.RLock()
	defer b.tidyStatusLock.RUnlock()

	resp := &logical.Response{
		Data: map[string]interface{}{
			"state":         "Inactive",
			"error":         nil,
			"time_started":  nil,
			"time_finished": nil,
			"message":       nil,
		},
	}

	if b.tidyStatus.state == tidyStatusInactive {
		return resp, nil
	}

	resp.Data["time_started"] = b.tidyStatus.timeStarted
	resp.Data["message"] = b.tidyStatus.message
	resp.Data["last_auto_tidy_finished"] = b.lastTidy

	switch b.tidyStatus.state {
	case tidyStatusStarted:
		resp.Data["state"] = "Running"
	case tidyStatusFinished:
		resp.Data["state"] = "Finished"
		resp.Data["time_finished"] = b.tidyStatus.timeFinished
		resp.Data["message"] = nil
	case tidyStatusError:
		resp.Data["state"] = "Error"
		resp.Data["time_finished"] = b.tidyStatus.timeFinished
		resp.Data["error"] = b.tidyStatus.err.Error()
		// Don't clear the message so that it serves as a hint about when
		// the error occurred.
	case tidyStatusCancelling:
		resp.Data["state"] = "Cancelling"
	case tidyStatusCancelled:
		resp.Data["state"] = "Cancelled"
		resp.Data["time_finished"] = b.tidyStatus.timeFinished
	}

	return resp, nil
}

func pathTidyCancel(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "tidy-cancel$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixACME,
			OperationVerb:   "tidy",
			OperationSuffix: "cancel",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathTidyCancelWrite,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"state": {
								Type:        framework.TypeString,
								Description: `One of Inactive, Running, Finished, or Error`,
								Required:    false,
							},
							"error": {
								Type:        framework.TypeString,
								Description: `The error message`,
								Required:    false,
							},
							"time_started": {
								Type:        framework.TypeString,
								Description: `Time the operation started`,
								Required:    false,
							},
							"time_finished": {
								Type:        framework.TypeString,
								Description: `Time the operation finished`,
								Required:    false,
							},
							"message": {
								Type:        framework.TypeString,
								Description: `Message of the operation`,
								Required:    false,
							},
						},
					}},
				},
				ForwardPerformanceStandby: true,
			},
		},
		HelpSynopsis:    pathTidyCancelHelpSyn,
		HelpDescription: pathTidyCancelHelpDesc,
	}
}

func pathTidyStatus(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "tidy-status$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixACME,
			OperationVerb:   "tidy",
			OperationSuffix: "status",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathTidyStatusRead,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"state": {
								Type:        framework.TypeString,
								Description: `One of Inactive, Running, Finished, or Error`,
								Required:    true,
							},
							"error": {
								Type:        framework.TypeString,
								Description: `The error message`,
								Required:    true,
							},
							"time_started": {
								Type:        framework.TypeString,
								Description: `Time the operation started`,
								Required:    true,
							},
							"time_finished": {
								Type:        framework.TypeString,
								Description: `Time the operation finished`,
								Required:    false,
							},
							"message": {
								Type:        framework.TypeString,
								Description: `Message of the operation`,
								Required:    true,
							},
						},
					}},
				},
				ForwardPerformanceStandby: true,
			},
		},
		HelpSynopsis:    pathTidyStatusHelpSyn,
		HelpDescription: pathTidyStatusHelpDesc,
	}
}

const pathTidyHelpSyn = `
Tidy up the backend by removing certificates that don't have any users.
`

const pathTidyHelpDesc = `
Tidy up the backend by removing certificates that don't have any users.
`

const pathTidyCancelHelpSyn = `
Cancels a currently running tidy operation.
`

const pathTidyCancelHelpDesc = `
This endpoint allows cancelling a currently running tidy operation.

Periodically throughout the invocation of tidy, we'll check if the operation
has been requested to be cancelled. If so, we'll stop the currently running
tidy operation.
`

const pathTidyStatusHelpSyn = `
Returns the status of the tidy operation.
`

const pathTidyStatusHelpDesc = `
This is a read only endpoint that returns information about the current tidy
operation, or the most recent if none is currently running.

The result includes the following fields:
* 'state': one of "Inactive", "Running", "Finished", "Error"
* 'error': the error message, if the operation ran into an error
* 'time_started': the time the operation started
* 'time_finished': the time the operation finished
* 'message': One of "Tidying certificate store: checking entry N of TOTAL" or
  "Tidying revoked certificates: checking certificate N of TOTAL"
`
