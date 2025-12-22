package domain

type Genre struct {
	ID   string `bson:"id" json:"id"`
	Name string `bson:"name" json:"name"`
	Desc string `bson:"desc,omitempty" json:"desc,omitempty"`
}
