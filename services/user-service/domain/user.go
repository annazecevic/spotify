package domain

type User struct {
	ID                  string `bson:"id"`
	Name                string `bson:"name"`
	LastName            string `bson:"last_name"`
	Email               string `bson:"email"`
	Username            string `bson:"username"`
	Password            string `bson:"password"`
	Confirmed           bool   `bson:"confirmed"`
	ConfirmationToken   string `bson:"confirmation_token"`
	TokenExpiresAt      int64  `bson:"token_expires_at"`
	PasswordResetToken  string `bson:"password_reset_token"`
	ResetTokenExpiresAt int64  `bson:"reset_token_expires_at"`
	OTPCode             string `bson:"otp_code"`
	OTPExpiresAt        int64  `bson:"otp_expires_at"`
	PasswordChangedAt   int64  `bson:"password_changed_at"`
	PasswordExpiresAt   int64  `bson:"password_expires_at"`
	CreatedAt           int64  `bson:"created_at"`
	UpdatedAt           int64  `bson:"updated_at"`
	Role                string `bson:"role"`
}
