# Account Manager - Secure Password Management System

Account Manager is a secure, server-side password management system built with Rust. It allows users to securely store and retrieve encrypted passwords for various websites and services. The system is designed with a microservice architecture, providing separation of concerns and enhanced security.

## Project Structure

```
.
├── Client/                  # Python client (under construction)
│   └── client.py
├── database/                # Database microservice for password storage
│   ├── src/
│   │   ├── main.rs          # Main service entry point
│   │   └── lib.rs           # Authentication middleware
│   └── Cargo.toml
├── middleware/              # API middleware service
│   ├── src/
│   │   ├── main.rs          # Main service entry point
│   │   ├── middleware.rs    # Authentication middleware
│   │   ├── server.rs        # Business logic and API handlers
│   │   └── lib.rs
│   └── Cargo.toml
└── storage/                 # User account storage microservice
    ├── src/
    │   ├── main.rs          # Main service entry point
    │   └── lib.rs           # Authentication middleware
    ├── accounts.db          # SQLite database for user accounts
    └── Cargo.toml
```

## Features

- **Secure Authentication**: Uses bcrypt for password hashing
- **Encrypted Password Storage**: AES-GCM encryption for all stored passwords
- **Token-based Authentication**: Secure tokens for service communication
- **User Management**: Registration, login, and account management
- **Password Management**: Add, retrieve, and manage website passwords
- **Admin Functions**: Monitor accounts and usage statistics

## Setup Instructions

### Prerequisites

- Rust (stable channel)
- SQLite
- Python 3.x (for client when available)

### Building the Services

1. **Database Service**:
   ```bash
   cd database
   cargo build --release
   ```

2. **Storage Service**:
   ```bash
   cd storage
   cargo build --release
   ```

3. **Middleware Service**:
   ```bash
   cd middleware
   cargo build --release
   ```

### Running the Services

Start each service in a separate terminal:

1. **Database Service**:
   ```bash
   cd database
   cargo run
   ```
   The service will start on port 51000.

2. **Storage Service**:
   ```bash
   cd storage
   cargo run
   ```
   The service will start on port 51001.

3. **Middleware Service**:
   ```bash
   cd middleware
   cargo run
   ```
   The service will start on port 51020.

## Architecture

- **Middleware Service**: Handles all client requests, authentication, and business logic
- **Storage Service**: Manages user accounts, credentials, and tokens
- **Database Service**: Stores encrypted password data for each user
- **Client**: Interfaces with the middleware service (under construction)

## API Endpoints

### Public Endpoints

- `POST /login` - User authentication
- `POST /register` - Create a new user account
- `POST /get_data` - Retrieve stored website entries (without passwords)
- `POST /add_data` - Add a new website password
- `POST /get_password` - Retrieve a specific password

### Protected Admin Endpoints

- `POST /api/admin_get_dates` - Retrieve account creation dates
- `POST /api/admin_get_tokens` - Retrieve all user tokens

## Security Features

- All passwords are hashed using bcrypt before storage
- Website passwords are encrypted using AES-GCM
- Communication between services uses token authentication
- Each service runs in isolation with limited permissions

## Client Development

The Python CLI client is currently under construction. This will provide a user-friendly interface for:
- Account management
- Password storage and retrieval
- Password generation
- Search capabilities

## Customizing the System

To modify service configurations:

1. Edit IP addresses and ports:
   - In `middleware/src/server.rs`, modify the `storage_ip()` and `database_ip()` functions
   - In each service's `database/src/main.rs`, adjust the bind address as needed

2. Change authentication tokens:
   - In `middleware/src/server.rs`, modify the `storage_token()` and `database_token()` functions
   - In each service's middleware implementation, update the token validation

## Contributing

If you're interested in contributing to the development of Account Manager, especially the Python client, please feel free to submit pull requests or open issues for discussion.

## Future Plans

- Complete Python CLI client
- Implement password sharing functionality
- Add password strength analysis