package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Username     string `gorm:"uniqueIndex;not null"`
	PasswordHash string `gorm:"not null"`
	IsAdmin      bool   `gorm:"default:false"`
	Permissions  []UserPermission
}

type UserPermission struct {
	gorm.Model
	UserID       uint   `gorm:"not null"`
	FolderPrefix string `gorm:"not null"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type CreateUserRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	IsAdmin  bool   `json:"is_admin"`
}

type AssignPermissionRequest struct {
	UserID       uint   `json:"user_id" binding:"required"`
	FolderPrefix string `json:"folder_prefix" binding:"required"`
}
