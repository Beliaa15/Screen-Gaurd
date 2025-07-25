# Physical Security System

A comprehensive security monitoring system using YOLOv8 and SAHI for real-time object detection, with features for monitoring mobile phones, screen recording tools, and system security enforcement.

## Features

- **Real-time Object Detection**: Uses YOLOv8 with SAHI for enhanced small object detection
- **Multi-factor Authentication**: Supports LDAP, face recognition, and fingerprint authentication
- **Security Monitoring**: Detects and alerts on screen recording tools and unauthorized activities
- **Session Management**: Secure session handling with timeout and activity monitoring
- **User Management**: GUI and CLI tools for managing user accounts and permissions
- **Security Overlay**: Device locking and access control
- **Comprehensive Logging**: Detailed security event logging and monitoring
- **Comprehensive Testing**: Full test suite with coverage reporting and automated testing
- **Modular Architecture**: Well-organized codebase with clear separation of concerns

## Project Structure

```
physical-security-system/
├── src/                           # Source code
│   ├── core/                      # Core modules
│   │   ├── __init__.py
│   │   ├── config.py             # Configuration settings
│   │   └── base.py               # Base classes and interfaces
│   ├── auth/                      # Authentication modules
│   │   ├── __init__.py
│   │   ├── auth_manager.py       # Main authentication manager
│   │   ├── ldap_auth.py          # LDAP authentication
│   │   ├── biometric_auth.py     # Face and fingerprint authentication
│   │   └── session_manager.py    # Session management
│   ├── detection/                 # Object detection modules
│   │   ├── __init__.py
│   │   ├── yolo_detector.py      # YOLO detection with SAHI
│   │   └── detector_service.py   # Main detection service
│   ├── security/                  # Security monitoring modules
│   │   ├── __init__.py
│   │   ├── alert_system.py       # Alert management
│   │   ├── system_monitor.py     # System process monitoring
│   │   └── process_manager.py    # Application process management
│   ├── ui/                        # User interface modules
│   │   ├── __init__.py
│   │   ├── gui_manager.py        # Main GUI interface
│   │   └── security_overlay.py   # Security overlay for device locking
│   └── utils/                     # Utility modules
│       ├── __init__.py
│       └── security_utils.py     # Security utilities and logging
├── scripts/                       # Management scripts
│   └── user_management.py        # User management utility
├── tests/                         # Test files
├── docs/                          # Documentation
├── models/                        # YOLO model files
├── logs/                          # Security logs
├── face_data/                     # Face recognition data
├── main.py                        # Main application entry point
└── requirements.txt               # Python dependencies
```

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Beliaa15/physical-security-system.git
   cd physical-security-system
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install additional packages for full functionality**:
   ```bash
   # For face recognition
   pip install face-recognition
   
   # For keyboard monitoring
   pip install keyboard
   
   # For Windows authentication (Windows only)
   pip install pywin32
   
   # For LDAP authentication
   pip install ldap3
   ```

4. **Download YOLO models**:
   - Place YOLO model files (e.g., `yolov8m.pt`, `yolov8n.pt`) in the `models/` directory
   - Or let the system download them automatically on first run

## Configuration

Edit `src/core/config.py` to customize system settings:

```python
# Authentication settings
AUTHENTICATION_REQUIRED = True
LDAP_SERVER = "ldap://your-server.com"
LDAP_BASE_DN = "your-domain.com"

# Detection settings
CONFIDENCE_THRESHOLD = 0.5
DEFAULT_CAMERA_INDEX = 0

# Session settings
SESSION_TIMEOUT = 8 * 60 * 60  # 8 hours
MAX_LOGIN_ATTEMPTS = 3
```

## Usage

### Starting the System

**With GUI (Recommended)**:
```bash
python main.py
```

**Command Line Only**:
```bash
python -m src.detection.detector_service --source 0 --view-img
```

### User Management

**GUI Interface**:
```bash
python scripts/user_management.py --gui
```

**Command Line**:
```bash
# Register a face
python scripts/user_management.py --register-face username --image-path /path/to/image.jpg

# Test authentication
python scripts/user_management.py --test-auth username --password password

# List registered faces
python scripts/user_management.py --list-faces
```

## Authentication Methods

### 1. LDAP Authentication
- Email and password authentication against Active Directory or LDAP server
- Role-based access control (Admin, Operator, User)
- Group membership validation

### 2. Face Recognition
- Register faces from camera or image files
- Real-time face recognition during authentication
- Encrypted face encoding storage

### 3. Fingerprint Authentication
- Windows Hello integration (Windows only)
- Mock implementation for testing on other platforms

## Security Features

### Object Detection
- **Mobile Phone Detection**: Alerts when mobile phones are detected in the camera view
- **Person Detection**: Tracks human presence for security monitoring
- **Real-time Processing**: Continuous video stream analysis

### Process Monitoring
- **Screen Recording Detection**: Monitors for OBS, Camtasia, Bandicam, and other recording tools
- **Keyboard Monitoring**: Detects Print Screen and Snipping Tool usage
- **NVIDIA Recording**: Detects NVIDIA Share/ShadowPlay recording activity

### Security Alerts
- **Full-screen Alerts**: Unmissable security violation notifications
- **Grace Periods**: Temporary allowance after password verification
- **Process Management**: Automatic minimization/restoration of applications

### Session Management
- **Automatic Timeout**: Sessions expire after inactivity
- **Activity Monitoring**: Tracks user activity for session validation
- **Secure Logout**: Proper session cleanup and device locking

## API Reference

### Core Classes

```python
from src.auth.auth_manager import AuthenticationManager
from src.detection.detector_service import DetectorService
from src.security.alert_system import AlertSystem

# Initialize authentication
auth_manager = AuthenticationManager()
if auth_manager.require_authentication():
    print("User authenticated successfully")

# Start detection service
detector = DetectorService()
detector.run_detection(source=0, view_img=True)

# Show security alert
alert_system = AlertSystem(Config())
alert_system.show_alert("Security violation detected", "mobile")
```

### Configuration

```python
from src.core.config import Config

# Access configuration settings
print(f"Camera index: {Config.DEFAULT_CAMERA_INDEX}")
print(f"Session timeout: {Config.SESSION_TIMEOUT}")
print(f"LDAP server: {Config.LDAP_SERVER}")
```

## Security Considerations

1. **Password Storage**: Passwords are encrypted and hashed using multiple layers
2. **Face Data**: Face encodings are encrypted and stored securely
3. **Session Security**: Sessions use secure tokens and automatic expiration
4. **Logging**: All security events are logged with timestamps and system info
5. **Access Control**: Multi-level authentication and role-based permissions

## Testing

The project includes a comprehensive test suite covering all modules and functionality.

### Quick Testing

**Run all tests**:
```bash
# Using the test runner script
python scripts/run_tests.py --all

# Or using pytest directly
pytest tests/ -v
```

**Run tests with coverage**:
```bash
python scripts/run_tests.py --coverage
```

### Test Categories

**Authentication Tests**:
```bash
python scripts/run_tests.py --auth
```

**Detection Tests**:
```bash
python scripts/run_tests.py --detection
```

**Security Tests**:
```bash
python scripts/run_tests.py --security
```

**UI Tests**:
```bash
python scripts/run_tests.py --ui
```

**Utility Tests**:
```bash
python scripts/run_tests.py --utils
```

### Test Runner Options

The `scripts/run_tests.py` script provides comprehensive testing capabilities:

```bash
# Install test dependencies
python scripts/run_tests.py --install-deps

# Run fast tests only (excludes slow integration tests)
python scripts/run_tests.py --fast

# Run unit tests only
python scripts/run_tests.py --unit

# Run integration tests only
python scripts/run_tests.py --integration

# Code formatting and linting
python scripts/run_tests.py --format --lint --imports

# Clean test cache and coverage files
python scripts/run_tests.py --clean
```

### Coverage Reports

After running tests with coverage, reports are generated in:
- **HTML Report**: `htmlcov/index.html` (open in browser)
- **Terminal**: Displays coverage summary
- **XML Report**: `coverage.xml` (for CI/CD integration)

### Test Configuration

Test configuration is managed in `pyproject.toml`:
- Test discovery patterns
- Coverage settings
- Test markers for categorization
- Warning filters

## Troubleshooting

### Common Issues

1. **Camera Not Found**:
   - Check camera connection and permissions
   - Verify `DEFAULT_CAMERA_INDEX` in config
   - Try different camera indices (0, 1, 2, etc.)

2. **Authentication Failures**:
   - Verify LDAP server settings
   - Check network connectivity
   - Ensure user accounts exist in LDAP

3. **Face Recognition Issues**:
   - Install `face-recognition` library
   - Ensure good lighting for face capture
   - Register faces with clear, front-facing images

4. **Permission Errors**:
   - Run as administrator for keyboard monitoring
   - Check file system permissions for logs and data directories

### Debug Mode

Set authentication to false for testing:
```python
# In src/core/config.py
AUTHENTICATION_REQUIRED = False
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue on GitHub
- Check the documentation in the `docs/` directory
- Review the security logs in the `logs/` directory

## Changelog

### Version 1.0.0
- Initial release with comprehensive security monitoring
- Multi-factor authentication support
- Real-time object detection with YOLO
- Security overlay and session management
- User management tools and GUI interface
