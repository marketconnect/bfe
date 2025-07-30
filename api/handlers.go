package api

import (
	"net/http"

	"github.com/marketconnect/bfe/auth"
	"github.com/marketconnect/bfe/db"
	"github.com/marketconnect/bfe/models"
	"github.com/marketconnect/bfe/storage_client"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	Store         db.Store
	StorageClient *storage_client.Client
	JwtSecret     string
}

// Auth Handlers
func (h *Handler) LoginHandler(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	user, err := h.Store.GetUserByUsername(req.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, err := auth.GenerateToken(user.ID, user.IsAdmin, h.JwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

// Admin Handlers
func (h *Handler) CreateUserHandler(c *gin.Context) {
	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	user := &models.User{
		Username:     req.Username,
		PasswordHash: string(hashedPassword),
		IsAdmin:      req.IsAdmin,
	}

	if err := h.Store.CreateUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create user", "details": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "user created successfully", "user_id": user.ID})
}

func (h *Handler) AssignPermissionHandler(c *gin.Context) {
	var req models.AssignPermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	perm := &models.UserPermission{
		UserID:       req.UserID,
		FolderPrefix: req.FolderPrefix,
	}

	if err := h.Store.AssignPermission(perm); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not assign permission", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "permission assigned successfully"})
}

// User Handlers
func (h *Handler) ListFilesHandler(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	permissions, err := h.Store.GetUserPermissions(userID.(uint))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve permissions"})
		return
	}

	if len(permissions) == 0 {
		c.JSON(http.StatusOK, gin.H{"files": []string{}})
		return
	}

	// For simplicity, we use the first permission. A real app might handle multiple.
	prefix := permissions[0].FolderPrefix

	objectKeys, err := h.StorageClient.ListObjects(prefix)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to list files from storage service", "details": err.Error()})
		return
	}

	type FileWithURL struct {
		Key string `json:"key"`
		URL string `json:"url"`
	}

	var filesWithURLs []FileWithURL
	// This can be slow. For production, consider a more efficient approach,
	// like generating URLs on the fly on the client or a dedicated endpoint.
	for _, key := range objectKeys {
		url, err := h.StorageClient.GeneratePresignedURL(key, 3600) // 1 hour expiry
		if err != nil {
			// Log the error but continue, so one failed URL doesn't break the whole list
			c.Error(err)
			continue
		}
		filesWithURLs = append(filesWithURLs, FileWithURL{Key: key, URL: url})
	}

	c.JSON(http.StatusOK, gin.H{"files": filesWithURLs})
}
