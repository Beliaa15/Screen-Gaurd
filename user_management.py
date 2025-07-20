"""
User Management Utility for Physical Security System

This utility allows administrators to:
- Register user faces for biometric authentication
- Manage user permissions and roles
- Test authentication methods
- View user activity logs
"""

import argparse
import sys
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from auth_manager import AuthenticationManager, BiometricAuthenticator
from security_utils import SecurityUtils, LDAPAuthenticator
from config import Config


class UserManagementGUI:
    """GUI for user management operations."""
    
    def __init__(self):
        self.auth_manager = AuthenticationManager()
        self.biometric_auth = BiometricAuthenticator()
        self.ldap_auth = LDAPAuthenticator(Config())
        
        self.root = tk.Tk()
        self.root.title("Physical Security System - User Management")
        self.root.geometry("800x600")
        self.root.configure(bg='lightgray')
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface."""
        # Title
        title_label = tk.Label(
            self.root,
            text="Physical Security System - User Management",
            font=("Helvetica", 16, "bold"),
            bg='lightgray',
            fg='darkblue'
        )
        title_label.pack(pady=20)
        
        # Main frame
        main_frame = tk.Frame(self.root, bg='lightgray')
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Face Registration Section
        face_frame = tk.LabelFrame(main_frame, text="Face Registration", font=("Helvetica", 12, "bold"), bg='lightgray')
        face_frame.pack(fill='x', pady=10)
        
        tk.Button(
            face_frame,
            text="Register Face from Camera",
            command=self.register_face_camera,
            font=("Helvetica", 11),
            bg='green',
            fg='white',
            width=25
        ).pack(pady=10, padx=10, side='left')
        
        tk.Button(
            face_frame,
            text="Register Face from Image",
            command=self.register_face_image,
            font=("Helvetica", 11),
            bg='blue',
            fg='white',
            width=25
        ).pack(pady=10, padx=10, side='left')
        
        # Authentication Testing Section
        test_frame = tk.LabelFrame(main_frame, text="Authentication Testing", font=("Helvetica", 12, "bold"), bg='lightgray')
        test_frame.pack(fill='x', pady=10)
        
        tk.Button(
            test_frame,
            text="Test LDAP Authentication",
            command=self.test_ldap_auth,
            font=("Helvetica", 11),
            bg='orange',
            fg='white',
            width=25
        ).pack(pady=10, padx=10, side='left')
        
        tk.Button(
            test_frame,
            text="Test Face Recognition",
            command=self.test_face_auth,
            font=("Helvetica", 11),
            bg='red',
            fg='white',
            width=25
        ).pack(pady=10, padx=10, side='left')
        
        tk.Button(
            test_frame,
            text="Test Fingerprint",
            command=self.test_fingerprint_auth,
            font=("Helvetica", 11),
            bg='purple',
            fg='white',
            width=25
        ).pack(pady=10, padx=10, side='left')
        
        # User Management Section
        user_frame = tk.LabelFrame(main_frame, text="User Management", font=("Helvetica", 12, "bold"), bg='lightgray')
        user_frame.pack(fill='x', pady=10)
        
        tk.Button(
            user_frame,
            text="List Registered Faces",
            command=self.list_registered_faces,
            font=("Helvetica", 11),
            bg='teal',
            fg='white',
            width=25
        ).pack(pady=10, padx=10, side='left')
        
        tk.Button(
            user_frame,
            text="Delete User Face",
            command=self.delete_user_face,
            font=("Helvetica", 11),
            bg='darkred',
            fg='white',
            width=25
        ).pack(pady=10, padx=10, side='left')
        
        # System Information Section
        info_frame = tk.LabelFrame(main_frame, text="System Information", font=("Helvetica", 12, "bold"), bg='lightgray')
        info_frame.pack(fill='x', pady=10)
        
        tk.Button(
            info_frame,
            text="View Security Logs",
            command=self.view_security_logs,
            font=("Helvetica", 11),
            bg='navy',
            fg='white',
            width=25
        ).pack(pady=10, padx=10, side='left')
        
        tk.Button(
            info_frame,
            text="System Status",
            command=self.show_system_status,
            font=("Helvetica", 11),
            bg='darkgreen',
            fg='white',
            width=25
        ).pack(pady=10, padx=10, side='left')
        
        # Output text area
        self.output_frame = tk.LabelFrame(main_frame, text="Output", font=("Helvetica", 12, "bold"), bg='lightgray')
        self.output_frame.pack(fill='both', expand=True, pady=10)
        
        self.output_text = tk.Text(
            self.output_frame,
            height=15,
            width=80,
            font=("Courier", 10),
            bg='black',
            fg='green',
            insertbackground='green'
        )
        
        scrollbar = tk.Scrollbar(self.output_frame, orient="vertical", command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=scrollbar.set)
        
        self.output_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Initial message
        self.log_output("Physical Security System User Management Utility")
        self.log_output("="*60)
        self.log_output("Ready for user management operations...")
    
    def log_output(self, message: str):
        """Log message to output text area."""
        self.output_text.insert(tk.END, f"{message}\n")
        self.output_text.see(tk.END)
        self.root.update()
    
    def register_face_camera(self):
        """Register user face from camera."""
        try:
            username = simpledialog.askstring("Register Face", "Enter username for face registration:")
            if not username:
                return
            
            self.log_output(f"Starting face registration for user: {username}")
            self.log_output("Position yourself in front of the camera and press SPACE when ready...")
            
            success = self.biometric_auth.register_face(username)
            
            if success:
                self.log_output(f"✅ Face registration successful for {username}")
                messagebox.showinfo("Success", f"Face registered successfully for {username}")
            else:
                self.log_output(f"❌ Face registration failed for {username}")
                messagebox.showerror("Error", f"Face registration failed for {username}")
                
        except Exception as e:
            self.log_output(f"❌ Error during face registration: {e}")
            messagebox.showerror("Error", f"Error during face registration: {e}")
    
    def register_face_image(self):
        """Register user face from image file."""
        try:
            username = simpledialog.askstring("Register Face", "Enter username for face registration:")
            if not username:
                return
            
            image_path = filedialog.askopenfilename(
                title="Select face image",
                filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp")]
            )
            
            if not image_path:
                return
            
            self.log_output(f"Registering face for {username} from image: {image_path}")
            
            success = self.biometric_auth.register_face(username, image_path)
            
            if success:
                self.log_output(f"✅ Face registration successful for {username}")
                messagebox.showinfo("Success", f"Face registered successfully for {username}")
            else:
                self.log_output(f"❌ Face registration failed for {username}")
                messagebox.showerror("Error", f"Face registration failed for {username}")
                
        except Exception as e:
            self.log_output(f"❌ Error during face registration: {e}")
            messagebox.showerror("Error", f"Error during face registration: {e}")
    
    def test_ldap_auth(self):
        """Test LDAP authentication."""
        try:
            username = simpledialog.askstring("LDAP Test", "Enter username:")
            if not username:
                return
            
            password = simpledialog.askstring("LDAP Test", "Enter password:", show='*')
            if not password:
                return
            
            self.log_output(f"Testing LDAP authentication for {username}...")
            
            success, role = self.ldap_auth.authenticate(username, password)
            
            if success:
                self.log_output(f"✅ LDAP authentication successful for {username} with role: {role}")
                messagebox.showinfo("Success", f"LDAP authentication successful!\nUser: {username}\nRole: {role}")
            else:
                self.log_output(f"❌ LDAP authentication failed for {username}: {role}")
                messagebox.showerror("Error", f"LDAP authentication failed: {role}")
                
        except Exception as e:
            self.log_output(f"❌ Error during LDAP test: {e}")
            messagebox.showerror("Error", f"Error during LDAP test: {e}")
    
    def test_face_auth(self):
        """Test face recognition authentication."""
        try:
            self.log_output("Starting face recognition test...")
            self.log_output("Look at the camera for face recognition...")
            
            result = self.biometric_auth.authenticate_face(timeout=30)
            
            if result:
                self.log_output(f"✅ Face recognition successful! Recognized user: {result}")
                messagebox.showinfo("Success", f"Face recognition successful!\nRecognized user: {result}")
            else:
                self.log_output("❌ Face recognition failed or timed out")
                messagebox.showerror("Error", "Face recognition failed or timed out")
                
        except Exception as e:
            self.log_output(f"❌ Error during face recognition test: {e}")
            messagebox.showerror("Error", f"Error during face recognition test: {e}")
    
    def test_fingerprint_auth(self):
        """Test fingerprint authentication."""
        try:
            self.log_output("Starting fingerprint test...")
            
            result = self.biometric_auth.authenticate_fingerprint()
            
            if result:
                self.log_output(f"✅ Fingerprint authentication successful! User: {result}")
                messagebox.showinfo("Success", f"Fingerprint authentication successful!\nUser: {result}")
            else:
                self.log_output("❌ Fingerprint authentication failed")
                messagebox.showerror("Error", "Fingerprint authentication failed")
                
        except Exception as e:
            self.log_output(f"❌ Error during fingerprint test: {e}")
            messagebox.showerror("Error", f"Error during fingerprint test: {e}")
    
    def list_registered_faces(self):
        """List all registered faces."""
        try:
            self.log_output("Registered faces in the system:")
            self.log_output("-" * 40)
            
            if not self.biometric_auth.face_encodings_db:
                self.log_output("No faces registered in the system")
            else:
                for i, username in enumerate(self.biometric_auth.face_encodings_db.keys(), 1):
                    self.log_output(f"{i}. {username}")
                
                self.log_output(f"\nTotal registered faces: {len(self.biometric_auth.face_encodings_db)}")
            
        except Exception as e:
            self.log_output(f"❌ Error listing registered faces: {e}")
    
    def delete_user_face(self):
        """Delete a user's face registration."""
        try:
            if not self.biometric_auth.face_encodings_db:
                messagebox.showinfo("Info", "No faces registered in the system")
                return
            
            usernames = list(self.biometric_auth.face_encodings_db.keys())
            username = simpledialog.askstring(
                "Delete Face", 
                f"Enter username to delete:\nRegistered users: {', '.join(usernames)}"
            )
            
            if not username:
                return
            
            if username not in self.biometric_auth.face_encodings_db:
                messagebox.showerror("Error", f"User '{username}' not found in face database")
                return
            
            # Confirm deletion
            if messagebox.askyesno("Confirm", f"Are you sure you want to delete face data for '{username}'?"):
                del self.biometric_auth.face_encodings_db[username]
                self.biometric_auth.save_face_encodings()
                
                self.log_output(f"✅ Face data deleted for user: {username}")
                messagebox.showinfo("Success", f"Face data deleted for user: {username}")
            
        except Exception as e:
            self.log_output(f"❌ Error deleting user face: {e}")
            messagebox.showerror("Error", f"Error deleting user face: {e}")
    
    def view_security_logs(self):
        """View recent security logs."""
        try:
            from datetime import datetime
            
            log_file = Path(Config.LOGS_DIR) / f"security_log_{datetime.now().strftime('%Y-%m-%d')}.txt"
            
            if not log_file.exists():
                self.log_output("No security log file found for today")
                return
            
            self.log_output("Recent security events:")
            self.log_output("=" * 50)
            
            with open(log_file, 'r') as f:
                lines = f.readlines()
                # Show last 20 lines
                for line in lines[-20:]:
                    self.log_output(line.strip())
            
        except Exception as e:
            self.log_output(f"❌ Error reading security logs: {e}")
    
    def show_system_status(self):
        """Show system status and configuration."""
        try:
            self.log_output("System Status and Configuration:")
            self.log_output("=" * 50)
            
            # Authentication status
            self.log_output(f"Authentication Required: {Config.AUTHENTICATION_REQUIRED}")
            self.log_output(f"Authentication Methods: {', '.join(Config.AUTHENTICATION_METHODS)}")
            
            # LDAP Configuration
            self.log_output(f"LDAP Server: {Config.LDAP_SERVER}")
            self.log_output(f"LDAP Base DN: {Config.LDAP_BASE_DN}")
            
            # Face Recognition
            try:
                import face_recognition
                self.log_output("Face Recognition: ✅ Available")
                self.log_output(f"Registered Faces: {len(self.biometric_auth.face_encodings_db)}")
            except ImportError:
                self.log_output("Face Recognition: ❌ Not Available")
            
            # Fingerprint
            try:
                import win32security
                self.log_output("Windows Fingerprint: ✅ Available")
            except ImportError:
                self.log_output("Windows Fingerprint: ❌ Not Available")
            
            # Session settings
            self.log_output(f"Session Timeout: {Config.SESSION_TIMEOUT} seconds")
            self.log_output(f"Idle Timeout: {Config.IDLE_TIMEOUT} seconds")
            self.log_output(f"Max Login Attempts: {Config.MAX_LOGIN_ATTEMPTS}")
            
        except Exception as e:
            self.log_output(f"❌ Error getting system status: {e}")
    
    def run(self):
        """Start the GUI."""
        self.root.mainloop()


class UserManagementCLI:
    """Command-line interface for user management."""
    
    def __init__(self):
        self.biometric_auth = BiometricAuthenticator()
        self.ldap_auth = LDAPAuthenticator(Config())
    
    def register_face(self, username: str, image_path: str = None):
        """Register face for a user."""
        print(f"Registering face for user: {username}")
        
        success = self.biometric_auth.register_face(username, image_path)
        
        if success:
            print(f"✅ Face registration successful for {username}")
        else:
            print(f"❌ Face registration failed for {username}")
        
        return success
    
    def test_auth(self, username: str, password: str):
        """Test LDAP authentication."""
        print(f"Testing authentication for: {username}")
        
        success, role = self.ldap_auth.authenticate(username, password)
        
        if success:
            print(f"✅ Authentication successful! Role: {role}")
        else:
            print(f"❌ Authentication failed: {role}")
        
        return success
    
    def list_faces(self):
        """List registered faces."""
        print("Registered faces:")
        print("-" * 30)
        
        if not self.biometric_auth.face_encodings_db:
            print("No faces registered")
        else:
            for i, username in enumerate(self.biometric_auth.face_encodings_db.keys(), 1):
                print(f"{i}. {username}")
        
        print(f"\nTotal: {len(self.biometric_auth.face_encodings_db)} registered faces")


def main():
    """Main function for user management utility."""
    parser = argparse.ArgumentParser(description="Physical Security System User Management")
    parser.add_argument("--gui", action="store_true", help="Launch GUI interface")
    parser.add_argument("--register-face", type=str, help="Register face for username")
    parser.add_argument("--image-path", type=str, help="Path to image file for face registration")
    parser.add_argument("--test-auth", type=str, help="Test authentication for username")
    parser.add_argument("--password", type=str, help="Password for authentication test")
    parser.add_argument("--list-faces", action="store_true", help="List registered faces")
    
    args = parser.parse_args()
    
    if args.gui:
        # Launch GUI
        app = UserManagementGUI()
        app.run()
    else:
        # Command-line interface
        cli = UserManagementCLI()
        
        if args.register_face:
            cli.register_face(args.register_face, args.image_path)
        elif args.test_auth:
            if not args.password:
                password = input("Enter password: ")
            else:
                password = args.password
            cli.test_auth(args.test_auth, password)
        elif args.list_faces:
            cli.list_faces()
        else:
            print("Physical Security System User Management Utility")
            print("Use --help for available options")
            print("Use --gui to launch the graphical interface")


if __name__ == "__main__":
    main()
