package dto

import "github.com/annazecevic/recommendation-service/domain"

type RecommendationResponse struct {
	SubscribedGenreTracks []domain.RecommendedTrack `json:"subscribed_genre_tracks"`
	TrendingTrack         *domain.RecommendedTrack  `json:"trending_track,omitempty"`
	Total                 int                       `json:"total"`
}
