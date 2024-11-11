// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package oauth2clientauthextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/oauth2clientauthextension"

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"go.uber.org/multierr"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"google.golang.org/grpc/credentials"
	grpcOAuth "google.golang.org/grpc/credentials/oauth"
)

// clientAuthenticator provides implementation for providing client authentication using OAuth2 client credentials
// workflow for both gRPC and HTTP clients.
type clientAuthenticator struct {
	clientCredentials *clientCredentialsConfig
	logger            *zap.Logger
	client            *http.Client
	headers           map[string]string
}

type errorWrappingTokenSource struct {
	ts       oauth2.TokenSource
	logger   *zap.Logger
	tokenURL string
}

type CustomTransport struct {
	BaseTransport http.RoundTripper
	Headers       map[string]string
	logger        *zap.Logger
}

func (ct *CustomTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Add custom headers to each request
	for key, value := range ct.Headers {
		req.Header.Set(key, value)
	}

	ct.logger.Info(fmt.Sprintf("Request Headers: %s",
		strings.Join(func() []string {
			var parts []string
			for k, values := range req.Header {
				for _, v := range values {
					parts = append(parts, fmt.Sprintf("%s: %s", k, v))
				}
			}
			return parts
		}(), ", ")))

	return ct.BaseTransport.RoundTrip(req)
}

// errorWrappingTokenSource implements TokenSource
var _ oauth2.TokenSource = (*errorWrappingTokenSource)(nil)

// errFailedToGetSecurityToken indicates a problem communicating with OAuth2 server.
var errFailedToGetSecurityToken = fmt.Errorf("failed to get security token from token endpoint")

func newClientAuthenticator(cfg *Config, logger *zap.Logger) (*clientAuthenticator, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	logger.Info("Getting newClientAuthenticator function")

	tlsCfg, err := cfg.TLSSetting.LoadTLSConfig()
	if err != nil {
		return nil, err
	}
	transport.TLSClientConfig = tlsCfg

	customTransport := &CustomTransport{
		BaseTransport: transport,
		Headers:       cfg.Headers,
		logger:        logger,
	}

	return &clientAuthenticator{
		clientCredentials: &clientCredentialsConfig{
			Config: clientcredentials.Config{
				ClientID:       cfg.ClientID,
				ClientSecret:   string(cfg.ClientSecret),
				TokenURL:       cfg.TokenURL,
				Scopes:         cfg.Scopes,
				EndpointParams: cfg.EndpointParams,
			},
			ClientIDFile:     cfg.ClientIDFile,
			ClientSecretFile: cfg.ClientSecretFile,
			logger:           logger,
		},
		logger: logger,
		client: &http.Client{
			Transport: customTransport,
			Timeout:   cfg.Timeout,
		},
		headers: cfg.Headers,
	}, nil
}

func (ewts errorWrappingTokenSource) Token() (*oauth2.Token, error) {
	ewts.logger.Info("Generating token inside extension")
	tok, err := ewts.ts.Token()
	if err != nil {
		return tok, multierr.Combine(
			fmt.Errorf("%w (endpoint %q)", errFailedToGetSecurityToken, ewts.tokenURL),
			err)
	}
	return tok, nil
}

// roundTripper returns oauth2.Transport, an http.RoundTripper that performs "client-credential" OAuth flow and
// also auto refreshes OAuth tokens as needed.
func (o *clientAuthenticator) roundTripper(base http.RoundTripper) (http.RoundTripper, error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, o.client)

	o.logger.Info("Getting round tripper function")

	return &oauth2.Transport{
		Source: errorWrappingTokenSource{
			ts:       o.clientCredentials.TokenSource(ctx),
			logger:   o.logger,
			tokenURL: o.clientCredentials.TokenURL,
		},
		Base: base,
	}, nil
}

// perRPCCredentials returns gRPC PerRPCCredentials that supports "client-credential" OAuth flow. The underneath
// oauth2.clientcredentials.Config instance will manage tokens performing auto refresh as necessary.
func (o *clientAuthenticator) perRPCCredentials() (credentials.PerRPCCredentials, error) {
	o.logger.Info("Got into RPC call")
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, o.client)
	return grpcOAuth.TokenSource{
		TokenSource: errorWrappingTokenSource{
			ts:       o.clientCredentials.TokenSource(ctx),
			logger:   o.logger,
			tokenURL: o.clientCredentials.TokenURL,
		},
	}, nil
}
