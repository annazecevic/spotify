package messaging

const (
	SubjectSubscriptionCreated = "subscription.created"
	SubjectSubscriptionDeleted = "subscription.deleted"
)

type SubscriptionCreatedEvent struct {
	UserID   string `json:"user_id"`
	Type     string `json:"type"`
	TargetID string `json:"target_id"`
	Name     string `json:"name"`
}

type SubscriptionDeletedEvent struct {
	UserID   string `json:"user_id"`
	Type     string `json:"type"`
	TargetID string `json:"target_id"`
}
