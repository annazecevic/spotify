package dto

type RegisterUserRequest struct {
	Name     string `json:"name" binding:"required"`
	LastName string `json:"last_name" binding:"required"`
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type ConfirmEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

type UserResponse struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	LastName          string `json:"last_name"`
	Username          string `json:"username"`
	Email             string `json:"email"`
	Role              string `json:"role"`
	Confirmed         bool   `json:"confirmed"`
	CreatedAt         int64  `json:"created_at"`
	PasswordExpiresAt int64  `json:"password_expires_at,omitempty"`
}

type LoginRequest struct {
	Identifier string `json:"identifier" binding:"required"`
	Password   string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Token                 string        `json:"token"`
	User                  *UserResponse `json:"user,omitempty"`
	PasswordExpiresSoon   bool          `json:"password_expires_soon,omitempty"`
	PasswordExpiresInDays int           `json:"password_expires_in_days,omitempty"`
}

type RequestPasswordResetRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

type VerifyOTPRequest struct {
	Email string `json:"email" binding:"required,email"`
	OTP   string `json:"otp" binding:"required"`
}

type RequestMagicLinkRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type VerifyMagicLinkRequest struct {
	Token string `json:"token" binding:"required"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
}

type UpdateProfileRequest struct {
	Name     string `json:"name,omitempty"`
	LastName string `json:"last_name,omitempty"`
	Username string `json:"username,omitempty"`
}
