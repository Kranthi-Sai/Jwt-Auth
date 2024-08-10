package models

type Users struct {
	ID       uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	Name     string `json:"name"`
	Email    string `gorm:"unique" json:"email"`
	Address  string `json:"address"`
	Password []byte `json:"-"`
}
