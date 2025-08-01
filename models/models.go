package models

import "time"

type User struct {
	ID           uint             `gorm:"primarykey" json:"id"`
	CreatedAt    time.Time        `json:"createdAt"`
	UpdatedAt    time.Time        `json:"updatedAt"`
	Username     string           `gorm:"uniqueIndex;not null" json:"username"`
	Alias        string           `json:"alias,omitempty"`
	PasswordHash string           `gorm:"not null" json:"-"`
	IsAdmin      bool             `gorm:"default:false" json:"isAdmin"`
	Permissions  []UserPermission `json:"permissions"`
}

type UserPermission struct {
	ID           uint      `gorm:"primarykey" json:"id"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	UserID       uint      `gorm:"not null;index" json:"userId"`
	FolderPrefix string    `gorm:"not null" json:"folderPrefix"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type FileWithURL struct {
	Key string `json:"key"`
	URL string `json:"url"`
}

type ListFilesResponse struct {
	Path    string        `json:"path"`
	Folders []string      `json:"folders"`
	Files   []FileWithURL `json:"files"`
}

type CreateUserRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Alias    string `json:"alias"`
	IsAdmin  bool   `json:"is_admin"`
}

type AssignPermissionRequest struct {
	UserID       uint   `json:"user_id" binding:"required,gte=1"`
	FolderPrefix string `json:"folder_prefix" binding:"required"`
}

type ResetPasswordRequest struct {
	Password string `json:"password" binding:"required"`
}

type UpdateAdminRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ArchiveRequest struct {
	Keys    []string `json:"keys"`
	Folders []string `json:"folders"`
}
