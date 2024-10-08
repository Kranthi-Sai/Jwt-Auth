package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	CreatedAt *time.Time     `json:"created_at,omitempty"`
	UpdatedAt *time.Time     `json:"updated_at,omitempty"`
	DeletedAt gorm.DeletedAt `json:"deleted_at,omitempty" gorm:"index"`
	ID        uint           `gorm:"primaryKey;autoIncrement" json:"id"`
	Name      string         `json:"name"`
	Email     string         `gorm:"unique" json:"email"`
	Address   string         `json:"address"`
	// Password  []byte         `json:"-"`
	Password string `gorm:"type:varchar(255);not null" json:"-"`
}

type OTP struct {
	ID        uint      `gorm:"primaryKey;autoIncrement"`
	UserID    uint      `gorm:"index"` // Foreign key to the User table
	User      User      `gorm:"constraint:OnDelete:CASCADE;"`
	Code      string    `gorm:"type:varchar(6);not null"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
}
