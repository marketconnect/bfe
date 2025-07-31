package db

import (
	"github.com/marketconnect/bfe/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Store interface {
	CreateUser(user *models.User) error
	UpdateUser(user *models.User) error
	DeleteUser(userID uint) error
	GetUserByID(userID uint) (*models.User, error)
	GetUserByUsername(username string) (*models.User, error)
	GetAllUsers() ([]models.User, error)
	AssignPermission(permission *models.UserPermission) error
	RevokePermission(permissionID uint) error
	GetUserPermissions(userID uint) ([]models.UserPermission, error)
}

type GormStore struct {
	DB *gorm.DB
}

func (s *GormStore) CreateUser(user *models.User) error {
	return s.DB.Create(user).Error
}

func (s *GormStore) UpdateUser(user *models.User) error {
	return s.DB.Save(user).Error
}

func (s *GormStore) DeleteUser(userID uint) error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		// Delete associated permissions first
		if err := tx.Where("user_id = ?", userID).Delete(&models.UserPermission{}).Error; err != nil {
			return err
		}
		// Then delete the user
		if err := tx.Delete(&models.User{Model: gorm.Model{ID: userID}}).Error; err != nil {
			return err
		}
		return nil
	})
}

func (s *GormStore) GetUserByID(userID uint) (*models.User, error) {
	var user models.User
	err := s.DB.Preload(clause.Associations).First(&user, userID).Error
	return &user, err
}

func (s *GormStore) GetUserByUsername(username string) (*models.User, error) {
	var user models.User
	err := s.DB.Preload(clause.Associations).Where("username = ?", username).First(&user).Error
	return &user, err
}

func (s *GormStore) GetAllUsers() ([]models.User, error) {
	var users []models.User
	err := s.DB.Preload("Permissions").Where("is_admin = ?", false).Find(&users).Error
	return users, err
}

func (s *GormStore) AssignPermission(permission *models.UserPermission) error {
	return s.DB.Create(permission).Error
}

func (s *GormStore) RevokePermission(permissionID uint) error {
	return s.DB.Delete(&models.UserPermission{}, permissionID).Error
}

func (s *GormStore) GetUserPermissions(userID uint) ([]models.UserPermission, error) {
	var permissions []models.UserPermission
	err := s.DB.Where("user_id = ?", userID).Find(&permissions).Error
	return permissions, err
}
