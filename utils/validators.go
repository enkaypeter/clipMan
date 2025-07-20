package utils

import (
	"encoding/base64"

	"github.com/go-playground/validator/v10"
)

func ValidateEncryptionKey(fl validator.FieldLevel) bool {
	key := fl.Field().String()
	if key == "" {
		return true // Allow empty key, as it's not required for unencrypted entries
	}

	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return false
	}

	return len(decoded) == 32
}
