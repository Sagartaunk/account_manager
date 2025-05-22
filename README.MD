# Account Manager - Secure Password Management System

Account Manager is a secure, server-side password management system built with Rust. It allows users to securely store and retrieve encrypted passwords for various websites and services. The system is designed with a microservice architecture, providing separation of concerns and enhanced security.

> **Note**: This project was created as a school project (prototype). A full Python version will also be available on my GitHub.

## Project Structure

```
.
├── Client/                  # Python client interface
│   └── client.py
├── database/                # Database microservice for password storage
│   ├── src/
│   │   ├── main.rs          # Main service entry point
│   │   └── lib.rs           # Authentication middleware
│   ├── data.db              # SQLite database for password data
│   └── Cargo.toml
├── middleware/              # API middleware service
│   ├── src/
│   │   ├── main.rs          # Main service entry point
│   │   ├── middleware.rs    # Authentication middleware
│   │   ├── server.rs        # Business logic and API handlers
│   │   └── lib.rs
│   ├── admin.txt            # Admin account credentials
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
- **Data Visualization**: Account creation date statistics with charts
- **Search Capability**: Find stored passwords by username or website

## Setup Instructions

### Prerequisites

- Rust (stable channel)
- SQLite
- Python 3.x with the following packages:
  - requests
  - pandas
  - matplotlib

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

4. **Client Application**:
   ```bash
   cd Client
   python client.py
   ```

## Architecture

- **Middleware Service**: Handles all client requests, authentication, and business logic
- **Storage Service**: Manages user accounts, credentials, and tokens
- **Database Service**: Stores encrypted password data for each user
- **Client**: Interfaces with the middleware service through a command-line interface

## API Endpoints

### Public Endpoints

- `POST /login` - User authentication
- `POST /register` - Create a new user account
- `POST /get_data` - Retrieve stored website entries (without passwords)
- `POST /add_data` - Add a new website password
- `POST /get_password` - Retrieve a specific password

### Protected Admin Endpoints

- `POST /api/admin_get_dates` - Retrieve account creation dates
- `POST /api/admin_create` - Create a new admin account

## Security Features

- All passwords are hashed using bcrypt before storage
- Website passwords are encrypted using AES-GCM
- Communication between services uses token authentication
- Each service runs in isolation with limited permissions
- Admin access requires special authentication

## Client Usage

The Python CLI client provides a command-line interface with the following commands:

- `Login`: Authenticate with existing credentials
- `Register`: Create a new user account
- `Get`: View stored website credentials (without passwords)
- `Add`: Store new website credentials
- `Decrypt`: Retrieve password for a specific website
- `Search`: Find entries by username or website
- `ADMIN`: Access admin functionality (requires admin credentials)
- `Help`: Display available commands
- `Exit`: Close the application

### Admin Commands

- `Dates`: View account creation dates with visualization
- `CreateAdmin`: Create a new admin account
- `Help`: Display admin commands
- `EXIT`: Return to main menu

## Customizing the System

To modify service configurations:

1. Edit IP addresses and ports:
   - In `middleware/src/server.rs`, modify the `storage_ip()` and `database_ip()` functions
   - In each service's `database/src/main.rs` file, adjust the bind address as needed

2. Change authentication tokens:
   - In `middleware/src/server.rs`, modify the `storage_token()` and `database_token()` functions
   - In each service's middleware implementation, update the token validation

## Contributing

If you're interested in contributing to the development of Account Manager, please feel free to submit pull requests or open issues for discussion.

## Future Plans

- Complete full Python version of the system
- Implement password sharing functionality
- Add password strength analysis
- Enhance data visualization capabilities
- Support for browser extensions
- Mobile application interface