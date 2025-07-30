package db

import (
	"github.com/marketconnect/bfe/models"

	"gorm.io/gorm"
)

type Store interface {
	CreateUser(user *models.User) error
	GetUserByUsername(username string) (*models.User, error)
	AssignPermission(permission *models.UserPermission) error
	GetUserPermissions(userID uint) ([]models.UserPermission, error)
}

type GormStore struct {
	DB *gorm.DB
}

func (s *GormStore) CreateUser(user *models.User) error {
	return s.DB.Create(user).Error
}

func (s *GormStore) GetUserByUsername(username string) (*models.User, error) {
	var user models.User
	err := s.DB.Where("username = ?", username).First(&user).Error
	return &user, err
}

func (s *GormStore) AssignPermission(permission *models.UserPermission) error {
	return s.DB.Create(permission).Error
}

func (s *GormStore) GetUserPermissions(userID uint) ([]models.UserPermission, error) {
	var permissions []models.UserPermission
	err := s.DB.Where("user_id = ?", userID).Find(&permissions).Error
	return permissions, err
}
