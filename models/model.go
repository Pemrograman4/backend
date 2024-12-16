package models

type User struct {
	ID       string `json:"id,omitempty" bson:"_id,omitempty"` // ID akan otomatis di-generate oleh MongoDB
	Username string `json:"username" bson:"username"`
	Email    string `json:"email" bson:"email"`
	Password string `json:"password" bson:"password"`
}