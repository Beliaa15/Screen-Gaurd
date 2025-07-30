"""
User Management Utility for Physical Security System

This utility allows administrators to:
- Register user faces for biometric authentication
- Manage user permissions and roles
- Test authentication methods
- View user activity logs
"""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import argparse
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog

from src.auth.auth_manager import AuthenticationManager
from src.auth.deepface_auth import DeepFaceAuthenticator
from src.utils.security_utils import SecurityUtils
from src.auth.ldap_auth import LDAPAuthenticator
from src.core.config import Config


class UserManagementGUI:
    """GUI for user management operations."""
    
    def __init__(self):
        self.auth_manager = AuthenticationManager()
        self.deepface_auth = DeepFaceAuthenticator()
        self.ldap_auth = LDAPAuthenticator(Config())
        
        self.root = tk.Tk()
        self.root.title("Physical Security System - User Management")
        self.root.geometry("900x700")
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
        
        # Face Registration Section - DeepFace (Advanced)
        deepface_frame = tk.LabelFrame(main_frame, text="Advanced Face Registration (DeepFace)", 
                                      font=("Helvetica", 12, "bold"), bg='lightgray')
        deepface_frame.pack(fill='x', pady=10)
        
        tk.Button(
            deepface_frame,
            text="Register Face (Camera) - Advanced",
            command=self.register_deepface_camera,
            font=("Helvetica", 11),
            bg='darkgreen',
            fg='white',
            width=30
        ).pack(pady=10, padx=10, side='left')
        
        tk.Button(
            deepface_frame,
            text="Register Face (Image) - Advanced",
            command=self.register_deepface_image,
            font=("Helvetica", 11),
            bg='darkblue',
            fg='white',
            width=30
        ).pack(pady=10, padx=10, side='left')
        
        tk.Button(
            deepface_frame,
            text="List DeepFace Users",
            command=self.list_deepface_users,
            font=("Helvetica", 11),
            bg='purple',
            fg='white',
            width=20
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
            width=20
        ).pack(pady=10, padx=10, side='left')
        
        tk.Button(
            test_frame,
            text="Test DeepFace Recognition",
            command=self.test_deepface_auth,
            font=("Helvetica", 11),
            bg='darkviolet',
            fg='white',
            width=20
        ).pack(pady=10, padx=10, side='left')

        tk.Button(
            test_frame,
            text="Test Fingerprint",
            command=self.test_fingerprint_auth,
            font=("Helvetica", 11),
            bg='red',
            fg='white',
            width=20
        ).pack(pady=10, padx=10, side='left')
        
        # User Management Section
        user_frame = tk.LabelFrame(main_frame, text="User Management", font=("Helvetica", 12, "bold"), bg='lightgray')
        user_frame.pack(fill='x', pady=10)
        
        tk.Button(
            user_frame,
            text="List Registered Faces",
            command=self.list_registered_faces,
            font=("Helvetica", 11),
            bg='darkgreen',
            fg='white',
            width=20
        ).pack(pady=10, padx=10, side='left')
        
        tk.Button(
            user_frame,
            text="Delete User Face",
            command=self.delete_user_face,
            font=("Helvetica", 11),
            bg='darkred',
            fg='white',
            width=20
        ).pack(pady=10, padx=10, side='left')
        
        # System Information Section
        system_frame = tk.LabelFrame(main_frame, text="System Information", font=("Helvetica", 12, "bold"), bg='lightgray')
        system_frame.pack(fill='x', pady=10)
        
        tk.Button(
            system_frame,
            text="View Security Logs",
            command=self.view_security_logs,
            font=("Helvetica", 11),
            bg='navy',
            fg='white',
            width=20
        ).pack(pady=10, padx=10, side='left')
        
        tk.Button(
            system_frame,
            text="System Status",
            command=self.show_system_status,
            font=("Helvetica", 11),
            bg='brown',
            fg='white',
            width=20
        ).pack(pady=10, padx=10, side='left')
        
        # Output text area
        output_frame = tk.LabelFrame(main_frame, text="Output", font=("Helvetica", 12, "bold"), bg='lightgray')
        output_frame.pack(fill='both', expand=True, pady=10)
        
        self.output_text = tk.Text(
            output_frame,
            height=15,
            font=("Courier", 10),
            bg='white',
            fg='black'
        )
        self.output_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Scrollbar for output
        scrollbar = tk.Scrollbar(output_frame, command=self.output_text.yview)
        scrollbar.pack(side='right', fill='y')
        self.output_text.config(yscrollcommand=scrollbar.set)
    
    def log_output(self, message: str):
        """Log message to output text area."""
        timestamp = SecurityUtils.get_system_info()['timestamp']
        formatted_message = f"[{timestamp}] {message}\n"
        self.output_text.insert(tk.END, formatted_message)
        self.output_text.see(tk.END)
        self.root.update_idletasks()
    
    def register_face_camera(self):
        """Register face from camera."""
        username = simpledialog.askstring("Username", "Enter username for face registration:")
        if not username:
            return
        
        self.log_output(f"Starting face registration for user: {username}")
        
        try:
            success = self.biometric_auth.register_face(username)
            if success:
                self.log_output(f"✅ Face registered successfully for {username}")
                messagebox.showinfo("Success", f"Face registered successfully for {username}")
            else:
                self.log_output(f"❌ Face registration failed for {username}")
                messagebox.showerror("Error", f"Face registration failed for {username}")
        except Exception as e:
            self.log_output(f"❌ Error during face registration: {e}")
            messagebox.showerror("Error", f"Face registration error: {e}")
    
    def register_face_image(self):
        """Register face from image file."""
        username = simpledialog.askstring("Username", "Enter username for face registration:")
        if not username:
            return
        
        image_path = filedialog.askopenfilename(
            title="Select face image",
            filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp")]
        )
        
        if not image_path:
            return
        
        self.log_output(f"Registering face from image for user: {username}")
        self.log_output(f"Image path: {image_path}")
        
        try:
            success = self.biometric_auth.register_face(username, image_path)
            if success:
                self.log_output(f"✅ Face registered successfully for {username}")
                messagebox.showinfo("Success", f"Face registered successfully for {username}")
            else:
                self.log_output(f"❌ Face registration failed for {username}")
                messagebox.showerror("Error", f"Face registration failed for {username}")
        except Exception as e:
            self.log_output(f"❌ Error during face registration: {e}")
            messagebox.showerror("Error", f"Face registration error: {e}")
    
    def test_ldap_auth(self):
        """Test LDAP authentication."""
        username = simpledialog.askstring("LDAP Test", "Enter username:")
        if not username:
            return
        
        password = simpledialog.askstring("LDAP Test", "Enter password:", show='*')
        if not password:
            return
        
        self.log_output(f"Testing LDAP authentication for user: {username}")
        
        try:
            success, result = self.ldap_auth.authenticate({
                'username': username,
                'password': password
            })
            
            if success:
                self.log_output(f"✅ LDAP authentication successful for {username}")
                self.log_output(f"User info: {result}")
                messagebox.showinfo("Success", f"LDAP authentication successful!\nUser: {username}\nRole: {result.get('role', 'Unknown') if isinstance(result, dict) else 'User'}")
            else:
                self.log_output(f"❌ LDAP authentication failed: {result}")
                messagebox.showerror("Error", f"LDAP authentication failed: {result}")
        except Exception as e:
            self.log_output(f"❌ LDAP authentication error: {e}")
            messagebox.showerror("Error", f"LDAP authentication error: {e}")
    
    def test_deepface_auth(self):
        """Test DeepFace recognition authentication."""
        self.log_output("Starting DeepFace recognition test...")
        
        try:
            result = self.deepface_auth.authenticate_face(timeout=30)
            if result:
                user_info = f"{result['first_name']} {result['last_name']} ({result['username']})"
                self.log_output(f"✅ DeepFace authentication successful for user: {user_info}")
                self.log_output(f"   - Role: {result['role']}")
                self.log_output(f"   - Email: {result['email']}")
                self.log_output(f"   - Euclidean Distance: {result['euclidean_distance']:.4f}")
                self.log_output(f"   - Cosine Similarity: {result['cosine_similarity']:.4f}")
                messagebox.showinfo("Success", f"DeepFace authentication successful!\n"
                                              f"User: {user_info}\n"
                                              f"Role: {result['role']}\n"
                                              f"Distance: {result['euclidean_distance']:.4f}")
            else:
                self.log_output("❌ DeepFace authentication failed or timed out")
                messagebox.showerror("Error", "DeepFace authentication failed or timed out")
        except Exception as e:
            self.log_output(f"❌ DeepFace authentication error: {e}")
            messagebox.showerror("Error", f"DeepFace authentication error: {e}")

    def register_deepface_camera(self):
        """Register face from camera using DeepFace."""
        # Get user information
        username = simpledialog.askstring("Username", "Enter username:")
        if not username:
            return
        
        first_name = simpledialog.askstring("First Name", "Enter first name:") or ""
        last_name = simpledialog.askstring("Last Name", "Enter last name:") or ""
        email = simpledialog.askstring("Email", "Enter email address:") or ""
        
        # Role selection
        role_window = tk.Toplevel(self.root)
        role_window.title("Select Role")
        role_window.geometry("300x200")
        role_window.transient(self.root)
        role_window.grab_set()
        
        role_var = tk.StringVar(value="user")
        
        tk.Label(role_window, text="Select user role:", font=("Helvetica", 12)).pack(pady=10)
        
        roles = [("User", "user"), ("Operator", "operator"), ("Admin", "admin")]
        for text, value in roles:
            tk.Radiobutton(role_window, text=text, variable=role_var, value=value,
                          font=("Helvetica", 10)).pack(anchor='w', padx=20)
        
        role_selected = [False]
        
        def confirm_role():
            role_selected[0] = True
            role_window.destroy()
        
        tk.Button(role_window, text="Confirm", command=confirm_role,
                 font=("Helvetica", 11), bg='green', fg='white').pack(pady=20)
        
        role_window.wait_window()
        
        if not role_selected[0]:
            return
        
        role = role_var.get()
        
        self.log_output(f"Registering DeepFace for user: {username} ({first_name} {last_name})")
        self.log_output(f"Role: {role}, Email: {email}")
        
        try:
            success = self.deepface_auth.register_face(username, first_name, last_name, email, role)
            if success:
                self.log_output(f"✅ DeepFace registered successfully for {username}")
                messagebox.showinfo("Success", f"DeepFace registered successfully for {username}")
            else:
                self.log_output(f"❌ DeepFace registration failed for {username}")
                messagebox.showerror("Error", f"DeepFace registration failed for {username}")
        except Exception as e:
            self.log_output(f"❌ Error during DeepFace registration: {e}")
            messagebox.showerror("Error", f"DeepFace registration error: {e}")

    def register_deepface_image(self):
        """Register face from image file using DeepFace."""
        # Get user information
        username = simpledialog.askstring("Username", "Enter username:")
        if not username:
            return
        
        first_name = simpledialog.askstring("First Name", "Enter first name:") or ""
        last_name = simpledialog.askstring("Last Name", "Enter last name:") or ""
        email = simpledialog.askstring("Email", "Enter email address:") or ""
        
        # Role selection (same as camera method)
        role_window = tk.Toplevel(self.root)
        role_window.title("Select Role")
        role_window.geometry("300x200")
        role_window.transient(self.root)
        role_window.grab_set()
        
        role_var = tk.StringVar(value="user")
        
        tk.Label(role_window, text="Select user role:", font=("Helvetica", 12)).pack(pady=10)
        
        roles = [("User", "user"), ("Operator", "operator"), ("Admin", "admin")]
        for text, value in roles:
            tk.Radiobutton(role_window, text=text, variable=role_var, value=value,
                          font=("Helvetica", 10)).pack(anchor='w', padx=20)
        
        role_selected = [False]
        
        def confirm_role():
            role_selected[0] = True
            role_window.destroy()
        
        tk.Button(role_window, text="Confirm", command=confirm_role,
                 font=("Helvetica", 11), bg='green', fg='white').pack(pady=20)
        
        role_window.wait_window()
        
        if not role_selected[0]:
            return
        
        role = role_var.get()
        
        # Select image file
        image_path = filedialog.askopenfilename(
            title="Select face image",
            filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp")]
        )
        
        if not image_path:
            return
        
        self.log_output(f"Registering DeepFace from image for user: {username} ({first_name} {last_name})")
        self.log_output(f"Role: {role}, Email: {email}")
        self.log_output(f"Image path: {image_path}")
        
        try:
            success = self.deepface_auth.register_face(username, first_name, last_name, email, role, image_path)
            if success:
                self.log_output(f"✅ DeepFace registered successfully for {username}")
                messagebox.showinfo("Success", f"DeepFace registered successfully for {username}")
            else:
                self.log_output(f"❌ DeepFace registration failed for {username}")
                messagebox.showerror("Error", f"DeepFace registration failed for {username}")
        except Exception as e:
            self.log_output(f"❌ Error during DeepFace registration: {e}")
            messagebox.showerror("Error", f"DeepFace registration error: {e}")

    def list_deepface_users(self):
        """List all DeepFace registered users."""
        self.log_output("Listing DeepFace registered users...")
        
        try:
            users = self.deepface_auth.list_registered_faces()
            if users:
                self.log_output(f"Found {len(users)} DeepFace registered users:")
                for user in users:
                    user_info = f"{user['username']} - {user['first_name']} {user['last_name']} ({user['role']})"
                    self.log_output(f"  - {user_info}")
                    if user['email']:
                        self.log_output(f"    Email: {user['email']}")
                    self.log_output(f"    Created: {user['created_at']}")
                
                # Show in dialog too
                users_info = []
                for user in users:
                    info = f"{user['username']} - {user['first_name']} {user['last_name']} ({user['role']})"
                    users_info.append(info)
                
                users_list = "\n".join(users_info)
                messagebox.showinfo("DeepFace Users", f"Registered users ({len(users)}):\n\n{users_list}")
            else:
                self.log_output("No DeepFace registered users found")
                messagebox.showinfo("DeepFace Users", "No DeepFace registered users found")
        except Exception as e:
            self.log_output(f"❌ Error listing DeepFace users: {e}")
            messagebox.showerror("Error", f"Error listing DeepFace users: {e}")

    def test_fingerprint_auth(self):
        """Test fingerprint authentication."""
        self.log_output("Starting fingerprint authentication test...")
        
        try:
            result = self.biometric_auth.authenticate_fingerprint()
            if result:
                self.log_output(f"✅ Fingerprint authentication successful for user: {result}")
                messagebox.showinfo("Success", f"Fingerprint authentication successful!\nUser: {result}")
            else:
                self.log_output("❌ Fingerprint authentication failed")
                messagebox.showerror("Error", "Fingerprint authentication failed")
        except Exception as e:
            self.log_output(f"❌ Fingerprint authentication error: {e}")
            messagebox.showerror("Error", f"Fingerprint authentication error: {e}")
    
    def list_registered_faces(self):
        """List all registered faces."""
        self.log_output("Listing registered faces...")
        
        try:
            face_db = self.biometric_auth.face_encodings_db
            if face_db:
                self.log_output(f"Found {len(face_db)} registered faces:")
                for username in face_db.keys():
                    self.log_output(f"  - {username}")
                
                # Show in dialog too
                users_list = "\n".join(face_db.keys())
                messagebox.showinfo("Registered Faces", f"Registered users ({len(face_db)}):\n\n{users_list}")
            else:
                self.log_output("No registered faces found")
                messagebox.showinfo("Registered Faces", "No registered faces found")
        except Exception as e:
            self.log_output(f"❌ Error listing faces: {e}")
            messagebox.showerror("Error", f"Error listing faces: {e}")
    
    def delete_user_face(self):
        """Delete a user's face registration."""
        username = simpledialog.askstring("Delete Face", "Enter username to delete:")
        if not username:
            return
        
        try:
            if username in self.biometric_auth.face_encodings_db:
                # Confirm deletion
                confirm = messagebox.askyesno("Confirm Deletion", 
                                            f"Are you sure you want to delete face registration for '{username}'?")
                if confirm:
                    del self.biometric_auth.face_encodings_db[username]
                    self.biometric_auth.save_face_encodings()
                    self.log_output(f"✅ Face registration deleted for user: {username}")
                    messagebox.showinfo("Success", f"Face registration deleted for {username}")
                else:
                    self.log_output(f"Face deletion cancelled for user: {username}")
            else:
                self.log_output(f"❌ No face registration found for user: {username}")
                messagebox.showwarning("Not Found", f"No face registration found for user: {username}")
        except Exception as e:
            self.log_output(f"❌ Error deleting face: {e}")
            messagebox.showerror("Error", f"Error deleting face: {e}")
    
    def view_security_logs(self):
        """View security logs."""
        self.log_output("Opening security logs viewer...")
        
        try:
            log_dir = Path(Config.LOGS_DIR)
            if not log_dir.exists():
                self.log_output("❌ Logs directory not found")
                messagebox.showwarning("Not Found", "Logs directory not found")
                return
            
            log_files = list(log_dir.glob("security_log_*.txt"))
            if not log_files:
                self.log_output("❌ No security log files found")
                messagebox.showinfo("No Logs", "No security log files found")
                return
            
            # Show latest log file
            latest_log = max(log_files, key=lambda f: f.stat().st_mtime)
            self.log_output(f"Displaying latest log: {latest_log.name}")
            
            # Create log viewer window
            log_window = tk.Toplevel(self.root)
            log_window.title(f"Security Log - {latest_log.name}")
            log_window.geometry("800x600")
            
            log_text = tk.Text(log_window, font=("Courier", 10))
            log_text.pack(fill='both', expand=True, padx=10, pady=10)
            
            scrollbar = tk.Scrollbar(log_window, command=log_text.yview)
            scrollbar.pack(side='right', fill='y')
            log_text.config(yscrollcommand=scrollbar.set)
            
            # Load and display log content
            with open(latest_log, 'r', encoding='utf-8') as f:
                content = f.read()
                log_text.insert('1.0', content)
            
            log_text.config(state='disabled')  # Make read-only
            
        except Exception as e:
            self.log_output(f"❌ Error viewing logs: {e}")
            messagebox.showerror("Error", f"Error viewing logs: {e}")
    
    def show_system_status(self):
        """Show system status information."""
        self.log_output("Gathering system status information...")
        
        try:
            sys_info = SecurityUtils.get_system_info()
            
            status_info = f"""
System Information:
- Computer: {sys_info['computer_name']}
- User: {sys_info['username']}
- IP Address: {sys_info['ip_address']}
- Platform: {sys_info['platform']} {sys_info['platform_version']}
- Architecture: {sys_info['architecture']}
- Processor: {sys_info['processor']}

Authentication Status:
- LDAP Available: {self.ldap_auth.is_available()}
- Biometric Available: {self.biometric_auth.is_available()}
- Registered Faces: {len(self.biometric_auth.face_encodings_db)}

Configuration:
- Authentication Required: {Config.AUTHENTICATION_REQUIRED}
- Session Timeout: {Config.SESSION_TIMEOUT} seconds
- Max Login Attempts: {Config.MAX_LOGIN_ATTEMPTS}
            """.strip()
            
            self.log_output("System status retrieved successfully")
            messagebox.showinfo("System Status", status_info)
            
        except Exception as e:
            self.log_output(f"❌ Error getting system status: {e}")
            messagebox.showerror("Error", f"Error getting system status: {e}")
    
    def run(self):
        """Run the GUI."""
        self.log_output("User Management GUI started")
        self.root.mainloop()


class UserManagementCLI:
    """Command-line interface for user management."""
    
    def __init__(self):
        self.deepface_auth = DeepFaceAuthenticator()
        self.ldap_auth = LDAPAuthenticator(Config())
    
    def register_face(self, username: str, image_path: str = None):
        """Register a face for the given username."""
        print(f"Registering face for user: {username}")
        
        try:
            success = self.biometric_auth.register_face(username, image_path)
            if success:
                print(f"✅ Face registered successfully for {username}")
            else:
                print(f"❌ Face registration failed for {username}")
        except Exception as e:
            print(f"❌ Error during face registration: {e}")
    
    def test_auth(self, username: str, password: str):
        """Test authentication for the given user."""
        print(f"Testing authentication for user: {username}")
        
        try:
            success, result = self.ldap_auth.authenticate({
                'username': username,
                'password': password
            })
            
            if success:
                print(f"✅ Authentication successful for {username}")
                print(f"User info: {result}")
            else:
                print(f"❌ Authentication failed: {result}")
        except Exception as e:
            print(f"❌ Authentication error: {e}")
    
    def list_faces(self):
        """List registered faces."""
        try:
            face_db = self.biometric_auth.face_encodings_db
            if face_db:
                print(f"Found {len(face_db)} registered faces:")
                for username in face_db.keys():
                    print(f"  - {username}")
            else:
                print("No registered faces found")
        except Exception as e:
            print(f"❌ Error listing faces: {e}")


def main():
    """Main function for user management utility."""
    parser = argparse.ArgumentParser(description="Physical Security System User Management")
    parser.add_argument("--gui", action="store_true", help="Launch GUI interface")
    parser.add_argument("--register-face", type=str, help="Register face for username")
    parser.add_argument("--image-path", type=str, help="Path to image file for face registration")
    parser.add_argument("--test-auth", type=str, help="Test authentication for username")
    parser.add_argument("--password", type=str, help="Password for authentication test")
    parser.add_argument("--list-faces", action="store_true", help="List registered faces")
    
    app = UserManagementGUI()
    app.run()
    


if __name__ == "__main__":
    main()
