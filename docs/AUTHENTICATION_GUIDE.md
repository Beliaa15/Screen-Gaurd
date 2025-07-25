# Authentication System User Guide (Without Face Recognition)

## Available Authentication Methods

### 1. Email & Password Authentication
- How to use: Click "Email & Password" on the login screen
- Requirements: Valid organization email and password
- Example: Enter your email (e.g., admin@security-local.com) and password
- Security: Uses LDAP authentication with your organization's Active Directory

### 2. Windows Hello Fingerprint Authentication (if available)
- How to use: Click "Fingerprint" on the login screen
- Requirements: Windows Hello configured with fingerprint reader
- Security: Uses Windows Biometric Framework for secure authentication

## Getting Started

### First Time Setup:
1. Run `python main.py` to start the secure monitoring system
2. Choose your preferred authentication method
3. Enter your credentials when prompted
4. System will start monitoring after successful authentication

### Daily Usage:
1. System starts with locked screen requiring authentication
2. Choose your authentication method
3. Once authenticated, monitoring begins automatically
4. System maintains your session based on activity
5. Use logout option when finished

### Session Management:
- Session Duration: Configurable timeout (default: 8 hours)
- Idle Timeout: Auto-lock after inactivity (default: 30 minutes)  
- Activity Tracking: Mouse/keyboard activity extends session
- Secure Logout: Clears all session data

## Security Features

- Account Lockout: Protection against brute force attacks
- Session Encryption: Secure session storage
- Activity Logging: All authentication events logged
- Real-time Monitoring: Continuous session validation

## System Administration

### Add New Users (LDAP):
- Contact your system administrator
- Users must exist in organization's Active Directory
- Roles: admin, operator, user

### Troubleshooting:
- Check logs in `logs/` directory for authentication issues
- Verify LDAP connectivity: `python test_ldap.py`
- Test authentication: `python test_authentication.py`

## Support

If you need face recognition in the future:
1. Install Visual Studio Build Tools
2. Run `python install_face_recognition.py`
3. Face recognition will be automatically enabled

Your system is secure and fully functional without face recognition!
