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
	*oauth2.Transport
	logger  *zap.Logger
	Headers map[string]string
}

func (ct *CustomTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ct.logger.Info("Got the round trip request via round tripper")
	// Add headers from the config to each request
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

	// Forward the request to the base RoundTripper
	return ct.Transport.RoundTrip(req)
}

type headerAddingTransport struct {
	transport http.RoundTripper
	logger    *zap.Logger
	headers   map[string]string
}

func (h *headerAddingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	h.logger.Info("Got the round trip request via grpc")
	for key, value := range h.headers {
		req.Header.Add(key, value)
	}

	h.logger.Info(fmt.Sprintf("Request Headers: %s",
		strings.Join(func() []string {
			var parts []string
			for k, values := range req.Header {
				for _, v := range values {
					parts = append(parts, fmt.Sprintf("%s: %s", k, v))
				}
			}
			return parts
		}(), ", ")))

	return h.transport.RoundTrip(req)
}

// errorWrappingTokenSource implements TokenSource
var _ oauth2.TokenSource = (*errorWrappingTokenSource)(nil)

// errFailedToGetSecurityToken indicates a problem communicating with OAuth2 server.
var errFailedToGetSecurityToken = fmt.Errorf("failed to get security token from token endpoint")

func newClientAuthenticator(cfg *Config, logger *zap.Logger) (*clientAuthenticator, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	logger.Info(fmt.Sprintf("Getting newClientAuthenticator function with headers: %s",
		strings.Join(func() []string {
			var parts []string
			for k, v := range cfg.Headers {
				parts = append(parts, fmt.Sprintf("%s: %s", k, v))
			}
			return parts
		}(), ", ")))

	tlsCfg, err := cfg.TLSSetting.LoadTLSConfig()
	if err != nil {
		return nil, err
	}
	transport.TLSClientConfig = tlsCfg

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
		},
		logger: logger,
		client: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
		},
		headers: cfg.Headers,
	}, nil
}

func (ewts errorWrappingTokenSource) Token() (*oauth2.Token, error) {
	ewts.logger.Info("Generating token")
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

	o.logger.Info(fmt.Sprintf("Getting round tripper function with headers: %s",
		strings.Join(func() []string {
			var parts []string
			for k, v := range o.headers {
				parts = append(parts, fmt.Sprintf("%s: %s", k, v))
			}
			return parts
		}(), ", ")))

	return &CustomTransport{
		Transport: &oauth2.Transport{
			Source: errorWrappingTokenSource{
				ts:       o.clientCredentials.TokenSource(ctx),
				logger:   o.logger,
				tokenURL: o.clientCredentials.TokenURL,
			},
			Base: base,
		},
		logger:  o.logger,
		Headers: o.headers,
	}, nil
}

// perRPCCredentials returns gRPC PerRPCCredentials that supports "client-credential" OAuth flow. The underneath
// oauth2.clientcredentials.Config instance will manage tokens performing auto refresh as necessary.
func (o *clientAuthenticator) perRPCCredentials() (credentials.PerRPCCredentials, error) {
	o.logger.Info("Get grpcOAuth token source")
	clientWithHeaders := &http.Client{
		Transport: &headerAddingTransport{
			transport: o.client.Transport,
			logger:    o.logger,
			headers:   o.headers,
		},
		Timeout: o.client.Timeout,
	}

	// Pass the custom HTTP client into the context.
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, clientWithHeaders)

	return grpcOAuth.TokenSource{
		TokenSource: errorWrappingTokenSource{
			ts:       o.clientCredentials.TokenSource(ctx),
			logger:   o.logger,
			tokenURL: o.clientCredentials.TokenURL,
		},
	}, nil
}
