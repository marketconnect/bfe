# BFE (Backend File Explorer)

A Go-based microservice that provides secure file management capabilities with user authentication and permission-based access control.

## Features

- User authentication with JWT tokens
- Role-based access control (Admin/User)
- File listing with presigned URLs
- Folder-based permission management
- PostgreSQL database integration
- Integration with external storage service

## Prerequisites

- Go 1.21 or higher
- PostgreSQL
- External storage service (compatible with S3-like API)

## Configuration

The service is configured using environment variables. Copy `.env.example` to `.env` and adjust the values:

```env
# Server configuration
SERVER_PORT=8080

# Database (PostgreSQL)
DB_HOST=localhost
DB_USER=postgres
DB_PASSWORD=secret
DB_NAME=main_service_db
DB_PORT=5432

# JWT Secret
JWT_SECRET_KEY=your-secret-key

# Storage Service URL
STORAGE_SERVICE_URL=http://localhost:8081
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/marketconnect/bfe.git
cd bfe
```

2. Install dependencies:
```bash
go mod download
```

3. Set up the environment variables (see Configuration section)

4. Run the service:
```bash
go run main.go
```

## API Endpoints

### Public Routes

- `POST /login` - Authenticate user and get JWT token

### Protected Routes (requires JWT token)

User Routes:
- `GET /files` - List files accessible to the authenticated user

Admin Routes (requires admin role):
- `POST /admin/users` - Create a new user
- `POST /admin/permissions` - Assign folder permissions to a user

## Authentication

The service uses JWT tokens for authentication. Include the token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

## Database Schema

The service uses two main database models:

### User
- ID (uint)
- Username (string, unique)
- PasswordHash (string)
- IsAdmin (bool)
- Timestamps (created_at, updated_at)

### UserPermission
- ID (uint)
- UserID (uint)
- FolderPrefix (string)
- Timestamps (created_at, updated_at)

## Project Structure

```
├── api/
│   ├── handlers.go    # HTTP request handlers
│   └── middleware.go  # Authentication middleware
├── auth/
│   └── jwt.go        # JWT token management
├── config/
│   └── config.go     # Configuration management
├── db/
│   ├── db.go         # Database initialization
│   └── store.go      # Database operations
├── models/
│   └── models.go     # Data models
├── storage_client/
│   └── client.go     # Storage service client
├── .env.example      # Example environment variables
├── go.mod           # Go module file
└── main.go          # Application entry point
```

