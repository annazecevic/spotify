package dto

type CreateSubscriptionRequest struct {
	Type     string `json:"type" binding:"required,oneof=ARTIST GENRE"`
	TargetID string `json:"target_id" binding:"required"`
}

type SubscriptionResponse struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	Type      string `json:"type"`
	TargetID  string `json:"target_id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

type SubscriptionsListResponse struct {
	Data  []SubscriptionResponse `json:"data"`
	Count int                    `json:"count"`
}
