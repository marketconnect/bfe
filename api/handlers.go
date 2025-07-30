package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/marketconnect/bfe/auth"
	"github.com/marketconnect/bfe/db"
	"github.com/marketconnect/bfe/models"
	"github.com/marketconnect/bfe/storage_client"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
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

func (h *Handler) ListUsersHandler(c *gin.Context) {
	users, err := h.Store.GetAllUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve users", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, users)
}

func (h *Handler) DeleteUserHandler(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.ParseUint(userIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID"})
		return
	}

	if err := h.Store.DeleteUser(uint(userID)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete user", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user deleted successfully"})
}

func (h *Handler) UpdateAdminSelfHandler(c *gin.Context) {
	adminID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req models.UpdateAdminRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Fetch the current admin user
	adminUser, err := h.Store.GetUserByID(adminID.(uint))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not find admin user"})
		return
	}

	// Update username if provided
	if req.Username != "" && req.Username != adminUser.Username {
		// Check if the new username is already taken by another user
		existingUser, err := h.Store.GetUserByUsername(req.Username)
		if err != nil && err != gorm.ErrRecordNotFound {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "database error while checking username"})
			return
		}
		// if err is nil, it means a user was found
		if err == nil && existingUser != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "username is already taken"})
			return
		}
		adminUser.Username = req.Username
	}

	// Update password if provided
	if req.Password != "" && req.Password != adminUser.PasswordHash {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
			return
		}
		adminUser.PasswordHash = string(hashedPassword)
	}

	if err := h.Store.UpdateUser(adminUser); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update admin account", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "admin account updated successfully"})
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

func (h *Handler) RevokePermissionHandler(c *gin.Context) {
	permissionIDStr := c.Param("id")
	permissionID, err := strconv.ParseUint(permissionIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid permission ID"})
		return
	}

	if err := h.Store.RevokePermission(uint(permissionID)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke permission", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "permission revoked successfully"})
}

func (h *Handler) ListAllFoldersHandler(c *gin.Context) {
	folders, err := h.StorageClient.ListAllFolders()
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to list folders from storage service", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"folders": folders})
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
		c.JSON(http.StatusOK, models.ListFilesResponse{Path: "/", Folders: []string{}, Files: []models.FileWithURL{}})
		return
	}

	requestedPath := c.Query("path")
	// If user is at root, show all their permitted folders instead of just the first one.
	if requestedPath == "" || requestedPath == "/" {
		var rootFolders []string
		for _, p := range permissions {
			rootFolders = append(rootFolders, p.FolderPrefix)
		}
		c.JSON(http.StatusOK, models.ListFilesResponse{
			Path:    "/",
			Folders: rootFolders,
			Files:   []models.FileWithURL{},
		})
		return
	}

	// Normalize path for security checks
	if !strings.HasSuffix(requestedPath, "/") {
		requestedPath += "/"
	}

	// Check if the user is allowed to access the requested path
	isAllowed := false
	for _, p := range permissions {
		if strings.HasPrefix(requestedPath, p.FolderPrefix) {
			isAllowed = true
			break
		}
	}

	if !isAllowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	// If allowed, proceed to list objects
	listOutput, err := h.StorageClient.ListObjects(requestedPath, "/")
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to list files from storage service", "details": err.Error()})
		return
	}

	var filesWithURLs []models.FileWithURL
	for _, key := range listOutput.Files {
		url, err := h.StorageClient.GeneratePresignedURL(key, 3600) // 1 hour expiry
		if err != nil {
			c.Error(err) // Log error
			continue
		}
		filesWithURLs = append(filesWithURLs, models.FileWithURL{Key: key, URL: url})
	}

	response := models.ListFilesResponse{
		Path:    requestedPath,
		Folders: listOutput.Folders,
		Files:   filesWithURLs,
	}

	c.JSON(http.StatusOK, response)
}
