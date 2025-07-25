# Physical Security System - Quick Start Guide

## 🚀 **New GUI Interface Available!**

Your Physical Security System now has a professional, full-screen GUI interface that provides a modern authentication experience.

## **How to Run the Application**

### ✅ **Recommended: New GUI Mode**
```bash
python main.py
```
**OR**
```bash
python launcher.py
```

This will show:
1. **Startup Screen** - Professional loading interface
2. **Login Screen** - Full-screen authentication with 3 options:
   - Username & Password (LDAP)
   - Fingerprint Scanner
   - Face Recognition
3. **Dashboard** - System status and control panel
4. **Automatic Detection** - Minimizes and starts monitoring

### 🎯 **Demo Mode (For Testing)**
```bash
python launcher.py --demo
```
- Tests the GUI with mock authentication
- No LDAP/biometric requirements
- Use username: `admin` or `test`

### 👥 **User Management**
```bash
python launcher.py --user-mgmt
```
- Register new faces
- Test authentication methods
- Manage user permissions

### ⚙️ **Legacy CLI Mode**
```bash
python launcher.py --legacy
```
- Original command-line interface
- No authentication required
- Direct detection mode

## **GUI Features**

### 🎨 **Visual Design**
- **Full-screen interface** (like your alert screens)
- **Professional dark theme**
- **Large, clear buttons and text**
- **Consistent with existing alert designs**

### 🔐 **Authentication Flow**
```
Device Startup → Loading Screen → Login Screen → Dashboard → Detection System
```

### 🖱️ **Easy to Use**
- Click authentication method on left panel
- Enter credentials or scan biometrics on right panel
- Visual feedback for all actions
- Clear error messages

### 📊 **System Status**
- Real-time authentication method availability
- Camera and system status
- User session information
- Professional logging

## **Test Credentials**

### For LDAP Testing
- Use your domain credentials
- Server: `192.168.1.26`
- Domain: `security-local.com`

### For Demo Mode
- Username: `admin`, `test`, or `user`
- Password: any password
- Fingerprint/Face: simulated successful scan

## **What Changed**

### ✅ **Before (CLI)**
```
🔐 Authentication Required
Please authenticate to access this secure device...
[Command line prompts]
```

### ✅ **Now (GUI)**
```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                    🛡️ SECURITY SYSTEM                        │
│                                                             │
│  🔑 USERNAME & PASSWORD    │    WELCOME                     │
│  👆 FINGERPRINT SCANNER    │                               │
│  👤 FACE RECOGNITION       │    Please select an           │
│                            │    authentication method      │
│  STATUS: 🟢 ALL READY      │    from the left panel        │
│                            │                               │
└─────────────────────────────────────────────────────────────┘
```

## **Integration**

The new GUI:
- ✅ **Maintains all existing functionality**
- ✅ **Uses your current authentication systems**
- ✅ **Preserves security logging**
- ✅ **Compatible with existing config**
- ✅ **Seamlessly starts detection after login**

## **Key Benefits**

1. **Professional Appearance** - Looks like real security software
2. **Better User Experience** - Clear, intuitive interface
3. **Enhanced Security** - Full-screen prevents access to desktop
4. **Consistent Design** - Matches your alert screen styling
5. **Easy Maintenance** - Modular, well-documented code

## **File Structure**

```
yolo8/
├── main.py              # ← Updated main entry point
├── gui_manager.py       # ← New GUI system
├── launcher.py          # ← Easy launcher script
├── test_gui.py          # ← GUI testing script
├── user_management.py   # ← Existing user management
├── detect.py            # ← Existing detection system
├── auth_manager.py      # ← Existing authentication
└── [other existing files]
```

Start with: **`python main.py`** and enjoy your new professional security interface! 🛡️
