package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPasswordHash(t *testing.T) {
	password := "snorkle"
	hashed, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	err = CheckPasswordHash(password, hashed)
	if err != nil {
		t.Fatal(err)
	}
}

func TestJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "scuba"

	token, err := MakeJWT(userID, tokenSecret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	parsedUserID, err := ValidateJWT(token, tokenSecret)
	if err != nil {
		t.Fatal(err)
	}

	if parsedUserID != userID {
		t.Fatal("User ID mismatch")
	}
}
