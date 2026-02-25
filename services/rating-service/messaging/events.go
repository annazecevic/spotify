package messaging

const (
	SubjectRatingCreated = "rating.created"
	SubjectRatingUpdated = "rating.updated"
	SubjectRatingDeleted = "rating.deleted"
)

type RatingEvent struct {
	UserID  string `json:"user_id"`
	TrackID string `json:"track_id"`
	Value   int    `json:"value"`
}

type RatingDeletedEvent struct {
	UserID  string `json:"user_id"`
	TrackID string `json:"track_id"`
}
