package gorpcbasicauth

import "context"

type BasicAuthCreds struct {
	username, password string
}

func (c *BasicAuthCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{
		"username": c.username,
		"password": c.password,
	}, nil
}

func (c *BasicAuthCreds) RequireTransportSecurity() bool {
	return true
}
