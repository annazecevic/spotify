package domain

type User struct {
	ID        string `bson:"id"`
	Name      string `bson:"name"`
	LastName  string `bson:"last_name"`
	Email     string `bson:"email"`
	Password  string `bson:"password"`
	Confirmed bool   `bson:"confirmed"`
	CreatedAt int64  `bson:"created_at"`
	UpdatedAt int64  `bson:"updated_at"`
	Role      string `bson:"role"`
}
