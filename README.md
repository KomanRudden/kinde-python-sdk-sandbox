# Kinde Auth Demo

A Flask-based demonstration application showcasing Kinde's authentication and authorization features. This demo provides a hands-on experience with Kinde's OAuth implementation, feature flags, permissions, and claims management.

## Features

- **Authentication**
  - Login/Register functionality
  - Token management (Access, ID, and Refresh tokens)
  - Token refresh mechanism
  - Secure logout

- **Feature Flags**
  - View all feature flags
  - Get individual feature flag status
  - Real-time flag updates

- **Permissions**
  - View all user permissions
  - Check individual permission status
  - Permission-based access control

- **Claims**
  - View all JWT claims
  - Get specific claim values
  - Token payload inspection

## Prerequisites

- Python 3.7+
- Flask
- Kinde account and API credentials

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd kinde-auth-demo
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the root directory with your Kinde credentials:
```env
KINDE_CLIENT_ID=your_client_id
KINDE_CLIENT_SECRET=your_client_secret
KINDE_REDIRECT_URI=http://localhost:5000/app_callback
KINDE_HOST=your_kinde_host
FLASK_SECRET_KEY=your_flask_secret_key
KINDE_SCOPES=openid profile email offline
```

## Running the Application

1. Start the Flask development server:
```bash
python app.py
```

2. Open your browser and navigate to:
```
http://localhost:5000
```

## Usage

### Authentication
- Click "Login" or "Register" to authenticate with Kinde
- View your tokens in the "Access Tokens" section
- Use the refresh button to get new tokens

### Feature Flags
- View all feature flags in the "Feature Flags" section
- Enter a flag code to check a specific flag's status
- Flags are updated in real-time when tokens are refreshed

### Permissions
- View all permissions in the "Permissions" section
- Enter a permission key to check specific permission status
- Permissions are managed through your Kinde dashboard

### Claims
- View all JWT claims in the "Claims" section
- Enter a claim name to view specific claim values
- Claims represent user attributes and token metadata

## Project Structure

```
kinde-auth-demo/
├── app.py              # Main Flask application
├── templates/          # HTML templates
│   ├── base.html      # Base template with common elements
│   └── index.html     # Main page template
├── .env               # Environment variables (create this)
├── .gitignore         # Git ignore file
└── requirements.txt   # Python dependencies
```

## Security Considerations

- Never commit your `.env` file
- Keep your Kinde credentials secure
- Use HTTPS in production
- Implement proper session management
- Follow OAuth 2.0 best practices


## Acknowledgments

- [Kinde](https://kinde.com) for providing the authentication service