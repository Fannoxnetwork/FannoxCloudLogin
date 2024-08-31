# FannoxCloudLogin Library

The `FannoxCloudLogin` library facilitates integration with the Fannox Cloud OAuth system, enabling client websites to authenticate users through Fannox Cloud. This library handles the OAuth 2.0 authorization code flow, manages session states, and retrieves user data upon successful authentication.

## Features

- **OAuth 2.0 Authorization Code Flow**: Securely authenticate users using the Fannox Cloud OAuth system.
- **State Management**: Ensures secure handling of state parameters to prevent CSRF attacks.
- **Access Token Exchange**: Safely exchanges authorization codes for access tokens.
- **User Data Retrieval**: Fetches authenticated user data using the obtained access token.
- **cURL-Based Requests**: Uses cURL for HTTP requests to communicate with the Fannox Cloud API.

## Requirements

- **PHP**: Version 7.2 or higher.
- **MySQL**: Database for storing user logins and managing OAuth states.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Fannoxnetwork/FannoxCloudLogin.git
