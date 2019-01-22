package gorpcbasicauth

import (
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/credentials"
)

func NewBasicAuthCreds(username, password string) (credentials.PerRPCCredentials, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return &BasicAuthCreds{}, err
	}

	return &BasicAuthCreds{username, string(bytes)}, nil
}
