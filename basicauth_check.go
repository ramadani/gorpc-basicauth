package gorpcbasicauth

import (
	"context"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func BasicAuthCheck(username, password string) func(ctx context.Context) (context.Context, error) {
	return func(ctx context.Context) (context.Context, error) {
		invalidData := status.Error(codes.Unauthenticated, "Invalid Basic Auth")
		invalidAuth := status.Error(codes.Unauthenticated, "Invalid Username or Password")

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return ctx, invalidData
		}

		if len(md["username"]) <= 0 || len(md["password"]) <= 0 {
			return ctx, invalidData
		}

		err := bcrypt.CompareHashAndPassword([]byte(md["password"][0]), []byte(password))

		if md["username"][0] != username || err != nil {
			return ctx, invalidAuth
		}

		return ctx, nil
	}
}
