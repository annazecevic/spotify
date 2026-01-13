package utils

import (
	"errors"
	"unicode"
)

func ValidatePasswordStrength(password string) error {
	if len(password) < 12 {
		return errors.New("password must be at least 12 characters long")
	}

	var (
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	commonPasswords := []string{
		"password", "Password123!", "Admin123!", "Welcome123!",
		"Qwerty123!", "Abc123456!", "Passw0rd!",
	}
	for _, common := range commonPasswords {
		if password == common {
			return errors.New("password is too common, please choose a different one")
		}
	}

	for i := 0; i < len(password)-3; i++ {
		if password[i] == password[i+1] && password[i] == password[i+2] && password[i] == password[i+3] {
			return errors.New("password cannot contain more than 3 consecutive repeating characters")
		}
	}

	return nil
}

func GenerateConfirmationToken() string {
	return randomString(32)
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[i%len(charset)]
	}
	return string(b)
}
