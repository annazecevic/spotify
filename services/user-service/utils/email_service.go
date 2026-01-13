package utils

import (
	"fmt"
	"net/smtp"
)

type EmailService interface {
	SendConfirmationEmail(to, username, token string) error
	SendPasswordResetEmail(to, username, token string) error
	SendOTPEmail(to, username, otpCode string) error
}

type emailService struct {
	smtpHost string
	smtpPort string
	username string
	password string
	from     string
	appURL   string
}

func NewEmailService(smtpHost, smtpPort, username, password, from, appURL string) EmailService {
	return &emailService{
		smtpHost: smtpHost,
		smtpPort: smtpPort,
		username: username,
		password: password,
		from:     from,
		appURL:   appURL,
	}
}

func (e *emailService) SendConfirmationEmail(to, username, token string) error {
	subject := "Confirm Your Email - Spotify Clone"
	confirmURL := fmt.Sprintf("%s/confirm-email?token=%s", e.appURL, token)
	
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #1DB954; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f4f4f4; }
        .button { display: inline-block; padding: 12px 30px; background-color: #1DB954; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to Spotify Clone!</h1>
        </div>
        <div class="content">
            <h2>Hi %s,</h2>
            <p>Thank you for registering! Please confirm your email address to activate your account.</p>
            <p>Click the button below to confirm your email:</p>
            <a href="%s" class="button">Confirm Email</a>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #1DB954;">%s</p>
            <p><strong>Note:</strong> This link will expire in 24 hours.</p>
            <p>If you didn't create this account, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>© 2026 Spotify Clone. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
`, username, confirmURL, confirmURL)

	return e.sendEmail(to, subject, body)
}

func (e *emailService) SendPasswordResetEmail(to, username, token string) error {
	subject := "Reset Your Password - Spotify Clone"
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", e.appURL, token)
	
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #1DB954; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f4f4f4; }
        .button { display: inline-block; padding: 12px 30px; background-color: #1DB954; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
        .warning { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 15px 0; }
        .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset Request</h1>
        </div>
        <div class="content">
            <h2>Hi %s,</h2>
            <p>We received a request to reset your password for your Spotify Clone account.</p>
            <p>Click the button below to reset your password:</p>
            <a href="%s" class="button">Reset Password</a>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #1DB954;">%s</p>
            <div class="warning">
                <strong>⚠️ Security Notice:</strong>
                <ul>
                    <li>This link will expire in 1 hour</li>
                    <li>If you didn't request this password reset, please ignore this email</li>
                    <li>Your password will not change unless you click the link above and create a new one</li>
                </ul>
            </div>
        </div>
        <div class="footer">
            <p>© 2026 Spotify Clone. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
`, username, resetURL, resetURL)

	return e.sendEmail(to, subject, body)
}

func (e *emailService) SendOTPEmail(to, username, otpCode string) error {
	subject := "Your One-Time Password - Spotify Clone"
	
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #1DB954; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f4f4f4; }
        .otp-box { background-color: white; border: 2px solid #1DB954; border-radius: 10px; padding: 30px; text-align: center; margin: 20px 0; }
        .otp-code { font-size: 36px; font-weight: bold; color: #1DB954; letter-spacing: 8px; font-family: monospace; }
        .warning { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 15px 0; }
        .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Two-Factor Authentication</h1>
        </div>
        <div class="content">
            <h2>Hi %s,</h2>
            <p>You have requested to log in to your Spotify Clone account. Please use the One-Time Password (OTP) below to complete your login:</p>
            
            <div class="otp-box">
                <p style="margin: 0; font-size: 14px; color: #666;">Your OTP Code:</p>
                <div class="otp-code">%s</div>
            </div>
            
            <div class="warning">
                <strong>⚠️ Security Notice:</strong>
                <ul>
                    <li>This code will expire in <strong>10 minutes</strong></li>
                    <li>Never share this code with anyone</li>
                    <li>If you didn't request this code, please ignore this email and secure your account</li>
                    <li>This code can only be used once</li>
                </ul>
            </div>
            
            <p style="margin-top: 20px;">If you're experiencing issues, please contact our support team.</p>
        </div>
        <div class="footer">
            <p>© 2026 Spotify Clone. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
`, username, otpCode)

	return e.sendEmail(to, subject, body)
}

func (e *emailService) sendEmail(to, subject, body string) error {
	if e.username == "" || e.password == "" {
		fmt.Printf("\n=== EMAIL WOULD BE SENT ===\nTo: %s\nSubject: %s\n===========================\n", to, subject)
		return nil
	}

	auth := smtp.PlainAuth("", e.username, e.password, e.smtpHost)

	headers := make(map[string]string)
	headers["From"] = e.from
	headers["To"] = to
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=UTF-8"

	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body

	addr := fmt.Sprintf("%s:%s", e.smtpHost, e.smtpPort)
	err := smtp.SendMail(addr, auth, e.from, []string{to}, []byte(message))
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

type mockEmailService struct{}

func NewMockEmailService() EmailService {
	return &mockEmailService{}
}

func (m *mockEmailService) SendConfirmationEmail(to, username, token string) error {
	confirmURL := fmt.Sprintf("http://localhost:3000/confirm-email?token=%s", token)
	fmt.Printf("\n=== CONFIRMATION EMAIL ===\nTo: %s\nUsername: %s\nConfirmation Link: %s\n==========================\n", to, username, confirmURL)
	return nil
}

func (m *mockEmailService) SendPasswordResetEmail(to, username, token string) error {
	resetURL := fmt.Sprintf("http://localhost:3000/reset-password?token=%s", token)
	fmt.Printf("\n=== PASSWORD RESET EMAIL ===\nTo: %s\nUsername: %s\nReset Link: %s\n============================\n", to, username, resetURL)
	return nil
}

func (m *mockEmailService) SendOTPEmail(to, username, otpCode string) error {
	fmt.Printf("\n=== OTP EMAIL ===\nTo: %s\nUsername: %s\nOTP Code: %s\n=================\n", to, username, otpCode)
	return nil
}
