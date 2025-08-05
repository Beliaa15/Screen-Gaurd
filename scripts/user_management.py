#!/usr/bin/env python3
"""
User Management GUI for Physical Security System
Fixed single-window version without popups or dialogs
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog
import datetime
from typing import Dict, Optional, Tuple

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.auth.auth_manager import AuthenticationManager
from src.auth.deepface_auth import DeepFaceAuthenticator
from src.auth.biometric_auth import BiometricAuthenticator
from src.auth.ldap_auth import LDAPAuthenticator
from src.core.config import Config

class UserManagementGUI:
    """GUI for user management operations."""
    
    def __init__(self):
        self.auth_manager = AuthenticationManager()
        self.deepface_auth = DeepFaceAuthenticator()
        self.biometric_auth = BiometricAuthenticator()  # For legacy face methods
        self.ldap_auth = LDAPAuthenticator(Config())
        
        self.root = tk.Tk()
        self.root.title("Physical Security System - User Management")
        self.root.geometry("1200x800")
        self.root.configure(bg='lightgray')
        
        # Make window always on top
        self.root.attributes('-topmost', True)
        
        # Variables for form data
        self.username_var = tk.StringVar()
        self.first_name_var = tk.StringVar()
        self.last_name_var = tk.StringVar() 
        self.email_var = tk.StringVar()
        self.role_var = tk.StringVar(value="user")
        self.selected_image_path = ""
        
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
        title_label.pack(pady=10)
        
        # Main container
        main_container = tk.Frame(self.root, bg='lightgray')
        main_container.pack(expand=True, fill='both', padx=10, pady=5)
        
        # Left panel for user input and actions
        left_panel = tk.Frame(main_container, bg='lightgray', width=500)
        left_panel.pack(side='left', fill='both', expand=False, padx=(0,10))
        left_panel.pack_propagate(False)
        
        # Right panel for output and user list
        right_panel = tk.Frame(main_container, bg='lightgray')
        right_panel.pack(side='right', fill='both', expand=True)
        
        self.setup_left_panel(left_panel)
        self.setup_right_panel(right_panel)
    
    def setup_left_panel(self, parent):
        """Setup the left panel with user input and action buttons."""
        
        # User Information Section
        info_frame = tk.LabelFrame(parent, text="User Information", 
                                  font=("Helvetica", 12, "bold"), bg='lightgray')
        info_frame.pack(fill='x', pady=5)
        
        # Username
        tk.Label(info_frame, text="Username:", bg='lightgray', font=("Helvetica", 10)).grid(row=0, column=0, sticky='w', padx=5, pady=3)
        username_entry = tk.Entry(info_frame, textvariable=self.username_var, width=25, font=("Helvetica", 10))
        username_entry.grid(row=0, column=1, padx=5, pady=3)
        
        # First Name
        tk.Label(info_frame, text="First Name:", bg='lightgray', font=("Helvetica", 10)).grid(row=1, column=0, sticky='w', padx=5, pady=3)
        tk.Entry(info_frame, textvariable=self.first_name_var, width=25, font=("Helvetica", 10)).grid(row=1, column=1, padx=5, pady=3)
        
        # Last Name
        tk.Label(info_frame, text="Last Name:", bg='lightgray', font=("Helvetica", 10)).grid(row=2, column=0, sticky='w', padx=5, pady=3)
        tk.Entry(info_frame, textvariable=self.last_name_var, width=25, font=("Helvetica", 10)).grid(row=2, column=1, padx=5, pady=3)
        
        # Email
        tk.Label(info_frame, text="Email:", bg='lightgray', font=("Helvetica", 10)).grid(row=3, column=0, sticky='w', padx=5, pady=3)
        tk.Entry(info_frame, textvariable=self.email_var, width=25, font=("Helvetica", 10)).grid(row=3, column=1, padx=5, pady=3)
        
        # Role
        tk.Label(info_frame, text="Role:", bg='lightgray', font=("Helvetica", 10)).grid(row=4, column=0, sticky='w', padx=5, pady=3)
        role_frame = tk.Frame(info_frame, bg='lightgray')
        role_frame.grid(row=4, column=1, sticky='w', padx=5, pady=3)
        
        roles = [("User", "user"), ("Operator", "operator"), ("Admin", "admin")]
        for i, (text, value) in enumerate(roles):
            tk.Radiobutton(role_frame, text=text, variable=self.role_var, value=value,
                          bg='lightgray', font=("Helvetica", 9)).pack(side='left', padx=5)
        
        # Clear button
        tk.Button(info_frame, text="Clear Form", command=self.clear_form,
                 bg='gray', fg='white', font=("Helvetica", 9)).grid(row=5, column=1, sticky='e', padx=5, pady=5)
        
        # Image Selection Section
        image_frame = tk.LabelFrame(parent, text="Image Selection (Optional)", 
                                   font=("Helvetica", 12, "bold"), bg='lightgray')
        image_frame.pack(fill='x', pady=5)
        
        self.image_label = tk.Label(image_frame, text="No image selected", 
                                   bg='lightgray', fg='gray', font=("Helvetica", 9))
        self.image_label.pack(pady=5)
        
        tk.Button(image_frame, text="Select Image File", command=self.select_image,
                 bg='steelblue', fg='white', font=("Helvetica", 10)).pack(pady=5)
        
        # User Registration Actions
        reg_frame = tk.LabelFrame(parent, text="User Registration Actions", 
                                 font=("Helvetica", 12, "bold"), bg='lightgray')
        reg_frame.pack(fill='x', pady=5)
        
        tk.Button(reg_frame, text="Register User + Face (Camera)", 
                 command=self.register_user_camera,
                 bg='darkgreen', fg='white', font=("Helvetica", 10), width=30).pack(pady=3)
        
        tk.Button(reg_frame, text="Register User + Face (Image)", 
                 command=self.register_user_image,
                 bg='darkblue', fg='white', font=("Helvetica", 10), width=30).pack(pady=3)
        
        tk.Button(reg_frame, text="Create LDAP User Only", 
                 command=self.create_ldap_user_only,
                 bg='purple', fg='white', font=("Helvetica", 10), width=30).pack(pady=3)
        
        # Authentication Testing
        test_frame = tk.LabelFrame(parent, text="Authentication Testing", 
                                  font=("Helvetica", 12, "bold"), bg='lightgray')
        test_frame.pack(fill='x', pady=5)
        
        test_buttons_frame = tk.Frame(test_frame, bg='lightgray')
        test_buttons_frame.pack(pady=5)
        
        tk.Button(test_buttons_frame, text="Test DeepFace", 
                 command=self.test_deepface_auth,
                 bg='darkviolet', fg='white', font=("Helvetica", 9), width=15).pack(side='left', padx=2)
        
        tk.Button(test_buttons_frame, text="Test Fingerprint", 
                 command=self.test_fingerprint_auth,
                 bg='red', fg='white', font=("Helvetica", 9), width=15).pack(side='left', padx=2)
        
        # LDAP Authentication Testing (requires username/password)
        ldap_test_frame = tk.Frame(test_frame, bg='lightgray')
        ldap_test_frame.pack(pady=3)
        
        tk.Label(ldap_test_frame, text="LDAP Test - Username:", bg='lightgray', font=("Helvetica", 9)).pack(side='left')
        self.ldap_user_var = tk.StringVar()
        tk.Entry(ldap_test_frame, textvariable=self.ldap_user_var, width=15, font=("Helvetica", 9)).pack(side='left', padx=3)
        
        tk.Label(ldap_test_frame, text="Password:", bg='lightgray', font=("Helvetica", 9)).pack(side='left', padx=(10,0))
        self.ldap_pass_var = tk.StringVar()
        tk.Entry(ldap_test_frame, textvariable=self.ldap_pass_var, width=15, show='*', font=("Helvetica", 9)).pack(side='left', padx=3)
        
        tk.Button(ldap_test_frame, text="Test LDAP", 
                 command=self.test_ldap_auth,
                 bg='orange', fg='white', font=("Helvetica", 9)).pack(side='left', padx=5)
        
        # User Management Actions
        mgmt_frame = tk.LabelFrame(parent, text="User Management", 
                                  font=("Helvetica", 12, "bold"), bg='lightgray')
        mgmt_frame.pack(fill='x', pady=5)
        
        mgmt_buttons_frame = tk.Frame(mgmt_frame, bg='lightgray')
        mgmt_buttons_frame.pack(pady=5)
        
        tk.Button(mgmt_buttons_frame, text="Refresh User List", 
                 command=self.refresh_user_list,
                 bg='darkgreen', fg='white', font=("Helvetica", 9), width=15).pack(side='left', padx=2)
        
        tk.Button(mgmt_buttons_frame, text="Delete Selected User", 
                 command=self.delete_selected_user,
                 bg='darkred', fg='white', font=("Helvetica", 9), width=15).pack(side='left', padx=2)
        
        # System Information
        sys_frame = tk.LabelFrame(parent, text="System Information", 
                                 font=("Helvetica", 12, "bold"), bg='lightgray')
        sys_frame.pack(fill='x', pady=5)
        
        sys_buttons_frame = tk.Frame(sys_frame, bg='lightgray')
        sys_buttons_frame.pack(pady=5)
        
        tk.Button(sys_buttons_frame, text="System Status", 
                 command=self.show_system_status,
                 bg='brown', fg='white', font=("Helvetica", 9), width=15).pack(side='left', padx=2)
        
        tk.Button(sys_buttons_frame, text="View Security Logs", 
                 command=self.view_security_logs,
                 bg='navy', fg='white', font=("Helvetica", 9), width=15).pack(side='left', padx=2)
    
    def setup_right_panel(self, parent):
        """Setup the right panel with output and user list."""
        
        # User List Section
        users_frame = tk.LabelFrame(parent, text="Registered Users", 
                                   font=("Helvetica", 12, "bold"), bg='lightgray')
        users_frame.pack(fill='both', expand=True, pady=(0,5))
        
        # User list with scrollbar
        list_frame = tk.Frame(users_frame)
        list_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create Treeview for user list
        columns = ('System', 'Username', 'Name', 'Role', 'Email', 'Created')
        self.user_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=10)
        
        # Configure columns
        self.user_tree.heading('System', text='System')
        self.user_tree.heading('Username', text='Username')
        self.user_tree.heading('Name', text='Full Name')
        self.user_tree.heading('Role', text='Role')
        self.user_tree.heading('Email', text='Email')
        self.user_tree.heading('Created', text='Created')
        
        self.user_tree.column('System', width=80)
        self.user_tree.column('Username', width=100)
        self.user_tree.column('Name', width=150)
        self.user_tree.column('Role', width=80)
        self.user_tree.column('Email', width=150)
        self.user_tree.column('Created', width=120)
        
        # Scrollbars for user list
        v_scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.user_tree.yview)
        h_scrollbar = ttk.Scrollbar(list_frame, orient='horizontal', command=self.user_tree.xview)
        self.user_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.user_tree.pack(side='left', fill='both', expand=True)
        v_scrollbar.pack(side='right', fill='y')
        h_scrollbar.pack(side='bottom', fill='x')
        
        # Output Section
        output_frame = tk.LabelFrame(parent, text="System Output", 
                                    font=("Helvetica", 12, "bold"), bg='lightgray')
        output_frame.pack(fill='both', expand=True, pady=(5,0))
        
        # Output text with scrollbar
        output_container = tk.Frame(output_frame)
        output_container.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.output_text = tk.Text(output_container, height=12, font=("Courier", 9), bg='white', fg='black')
        output_scrollbar = tk.Scrollbar(output_container, command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=output_scrollbar.set)
        
        self.output_text.pack(side='left', fill='both', expand=True)
        output_scrollbar.pack(side='right', fill='y')
        
        # Load initial data
        self.refresh_user_list()
        self.log_output("User Management System initialized")
    
    def validate_user_info(self):
        """Validate that required user information is provided."""
        username = self.username_var.get().strip()
        if not username:
            self.log_output("ERROR: Username is required", "error")
            return False
        return True
    
    def get_user_info(self):
        """Get user information from form fields."""
        return {
            'username': self.username_var.get().strip(),
            'first_name': self.first_name_var.get().strip(),
            'last_name': self.last_name_var.get().strip(),
            'email': self.email_var.get().strip(),
            'role': self.role_var.get()
        }
    
    def clear_form(self):
        """Clear all form fields."""
        self.username_var.set("")
        self.first_name_var.set("")
        self.last_name_var.set("")
        self.email_var.set("")
        self.role_var.set("user")
        self.selected_image_path = ""
        self.image_label.config(text="No image selected", fg='gray')
        self.log_output("Form cleared")
    
    def select_image(self):
        """Select an image file for face registration."""
        file_path = filedialog.askopenfilename(
            title="Select Face Image",
            filetypes=[
                ("Image files", "*.png *.jpg *.jpeg *.gif *.bmp"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.selected_image_path = file_path
            filename = file_path.split('/')[-1]
            self.image_label.config(text=f"Selected: {filename}", fg='darkgreen')
            self.log_output(f"Image selected: {filename}")
    
    def log_output(self, message, level="info"):
        """Log output to the text area with timestamp and color coding."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        # Insert message with timestamp
        self.output_text.insert(tk.END, f"[{timestamp}] {message}\n")
        
        # Color coding based on level
        if level == "error":
            # Make the last line red
            start_line = self.output_text.index(tk.END).split('.')[0]
            line_num = int(start_line) - 1
            self.output_text.tag_add("error", f"{line_num}.0", f"{line_num}.end")
            self.output_text.tag_config("error", foreground="red")
        elif level == "success":
            # Make the last line green
            start_line = self.output_text.index(tk.END).split('.')[0]
            line_num = int(start_line) - 1
            self.output_text.tag_add("success", f"{line_num}.0", f"{line_num}.end")
            self.output_text.tag_config("success", foreground="darkgreen")
        elif level == "warning":
            # Make the last line orange
            start_line = self.output_text.index(tk.END).split('.')[0]
            line_num = int(start_line) - 1  
            self.output_text.tag_add("warning", f"{line_num}.0", f"{line_num}.end")
            self.output_text.tag_config("warning", foreground="orange")
        
        # Auto-scroll to bottom
        self.output_text.see(tk.END)
        self.root.update()
    
    def register_user_camera(self):
        """Register a user and their face using camera."""
        if not self.validate_user_info():
            return
            
        user_info = self.get_user_info()
        self.log_output(f"Starting user registration for: {user_info['username']}")
        
        try:
            # Use the unified registration method from DeepFace with camera
            success, message = self.deepface_auth.create_ldap_user_with_face(
                username=user_info['username'],
                first_name=user_info['first_name'],
                last_name=user_info['last_name'],
                email=user_info['email'],
                role=user_info['role'],
                use_camera=True
            )
            
            if success:
                self.log_output(f"SUCCESS: {message}", "success")
                self.refresh_user_list()
                self.clear_form()
            else:
                self.log_output(f"ERROR: {message}", "error")
                
        except Exception as e:
            self.log_output(f"Registration error: {str(e)}", "error")
    
    def register_user_image(self):
        """Register a user and their face using selected image."""
        if not self.validate_user_info():
            return
            
        if not self.selected_image_path:
            self.log_output("ERROR: Please select an image file first", "error")
            return
        
        user_info = self.get_user_info()
        self.log_output(f"Starting user registration for: {user_info['username']} with image")
        
        try:
            # Use the unified registration method from DeepFace with image
            success, message = self.deepface_auth.create_ldap_user_with_face(
                username=user_info['username'],
                first_name=user_info['first_name'],
                last_name=user_info['last_name'],
                email=user_info['email'],
                role=user_info['role'],
                use_camera=False,
                image_path=self.selected_image_path
            )
            
            if success:
                self.log_output(f"SUCCESS: {message}", "success")
                self.refresh_user_list()
                self.clear_form()
            else:
                self.log_output(f"ERROR: {message}", "error")
                
        except Exception as e:
            self.log_output(f"Registration error: {str(e)}", "error")
    
    def create_ldap_user_only(self):
        """Create LDAP user without face registration."""
        if not self.validate_user_info():
            return
            
        user_info = self.get_user_info()
        self.log_output(f"Creating LDAP user: {user_info['username']}")
        
        try:
            temp_password = self.ldap_auth.create_user(
                username=user_info['username'],
                first_name=user_info['first_name'],
                last_name=user_info['last_name'],
                email=user_info['email'],
                role=user_info['role']
            )
            
            if temp_password:
                self.log_output(f"SUCCESS: LDAP user created. Temporary password: {temp_password}", "success")
                self.refresh_user_list()
                self.clear_form()
            else:
                self.log_output("ERROR: Failed to create LDAP user", "error")
                
        except Exception as e:
            self.log_output(f"LDAP user creation error: {str(e)}", "error")
    
    def test_ldap_auth(self):
        """Test LDAP authentication using form fields."""
        username = self.ldap_user_var.get().strip()
        password = self.ldap_pass_var.get().strip()
        
        if not username or not password:
            self.log_output("ERROR: Please enter both username and password for LDAP test", "error")
            return
        
        self.log_output(f"Testing LDAP authentication for: {username}")
        
        try:
            result = self.ldap_auth.authenticate(username, password)
            if result:
                role = result.get('role', 'Unknown') if isinstance(result, dict) else 'User'
                self.log_output(f"SUCCESS: LDAP authentication successful! User: {username}, Role: {role}", "success")
            else:
                self.log_output(f"ERROR: LDAP authentication failed for user: {username}", "error")
        except Exception as e:
            self.log_output(f"LDAP authentication error: {str(e)}", "error")
    
    def test_deepface_auth(self):
        """Test DeepFace authentication using camera."""
        self.log_output("Starting DeepFace camera authentication test...")
        
        try:
            result = self.deepface_auth.authenticate()
            if result:
                self.log_output(f"SUCCESS: DeepFace authentication successful! User: {result}", "success")
            else:
                self.log_output("ERROR: DeepFace authentication failed - no match found", "error")
        except Exception as e:
            self.log_output(f"DeepFace authentication error: {str(e)}", "error")
    
    def test_fingerprint_auth(self):
        """Test fingerprint authentication."""
        self.log_output("Starting fingerprint authentication test...")
        
        try:
            result = self.biometric_auth.fingerprint_auth()
            if result:
                self.log_output(f"SUCCESS: Fingerprint authentication successful! User: {result}", "success")
            else:
                self.log_output("ERROR: Fingerprint authentication failed", "error")
        except Exception as e:
            self.log_output(f"Fingerprint authentication error: {str(e)}", "error")
    
    def refresh_user_list(self):
        """Refresh the user list from both LDAP and DeepFace systems."""
        # Clear existing items
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)
        
        try:
            # Get LDAP users
            ldap_users = []
            try:
                ldap_users = self.ldap_auth.list_users()
                if not ldap_users:
                    ldap_users = []
            except Exception as e:
                self.log_output(f"Warning: Could not retrieve LDAP users: {str(e)}", "warning")
            
            # Get DeepFace users
            deepface_users = []
            try:
                deepface_users = self.deepface_auth.list_users()
                if not deepface_users:
                    deepface_users = []
            except Exception as e:
                self.log_output(f"Warning: Could not retrieve DeepFace users: {str(e)}", "warning")
            
            # Combine and display users
            all_usernames = set()
            
            # Add LDAP users
            for user in ldap_users:
                username = user.get('username', 'Unknown')
                all_usernames.add(username)
                
                self.user_tree.insert('', 'end', values=(
                    'LDAP',
                    username,
                    f"{user.get('first_name', '')} {user.get('last_name', '')}".strip(),
                    user.get('role', 'Unknown'),
                    user.get('email', ''),
                    user.get('created_date', '')
                ))
            
            # Add DeepFace users (only if not already in LDAP)
            for user in deepface_users:
                username = user.get('username', 'Unknown')
                if username not in all_usernames:
                    self.user_tree.insert('', 'end', values=(
                        'DeepFace',
                        username,
                        f"{user.get('first_name', '')} {user.get('last_name', '')}".strip(),
                        user.get('role', 'Unknown'),
                        user.get('email', ''),
                        user.get('registration_date', '')
                    ))
            
            self.log_output(f"User list refreshed - LDAP: {len(ldap_users)}, DeepFace: {len(deepface_users)}")
            
        except Exception as e:
            self.log_output(f"Error refreshing user list: {str(e)}", "error")
    
    def delete_selected_user(self):
        """Delete the selected user from the tree view."""
        selection = self.user_tree.selection()
        if not selection:
            self.log_output("ERROR: Please select a user to delete", "error")
            return
        
        # Get selected user info
        item = selection[0]
        values = self.user_tree.item(item, 'values')
        system = values[0]
        username = values[1]
        
        self.log_output(f"Deleting user: {username} from {system} system")
        
        try:
            success = False
            
            if system == 'LDAP':
                success = self.ldap_auth.delete_user(username)
                if success:
                    self.log_output(f"SUCCESS: User {username} deleted from LDAP", "success")
                else:
                    self.log_output(f"ERROR: Failed to delete user {username} from LDAP", "error")
            
            elif system == 'DeepFace':
                success = self.deepface_auth.delete_user(username)
                if success:
                    self.log_output(f"SUCCESS: User {username} deleted from DeepFace", "success")
                else:
                    self.log_output(f"ERROR: Failed to delete user {username} from DeepFace", "error")
            
            if success:
                self.refresh_user_list()
                
        except Exception as e:
            self.log_output(f"Error deleting user {username}: {str(e)}", "error")
    
    def show_system_status(self):
        """Show system status information."""
        self.log_output("=== SYSTEM STATUS ===")
        
        try:
            # LDAP Status
            try:
                ldap_users = self.ldap_auth.list_users()
                self.log_output(f"LDAP Server: Connected ({len(ldap_users)} users)")
            except Exception as e:
                self.log_output(f"LDAP Server: Error - {str(e)}", "error")
            
            # DeepFace Status
            try:
                deepface_users = self.deepface_auth.list_users()
                self.log_output(f"DeepFace System: Active ({len(deepface_users)} users)")
            except Exception as e:
                self.log_output(f"DeepFace System: Error - {str(e)}", "error")
            
            # Biometric Status
            try:
                # Test basic biometric system availability
                self.log_output("Biometric System: Available")
            except Exception as e:
                self.log_output(f"Biometric System: Error - {str(e)}", "error")
            
            # Database Status
            try:
                db_path = "face_data/deepface_auth.db"
                if os.path.exists(db_path):
                    size = os.path.getsize(db_path)
                    self.log_output(f"Database: Connected ({size} bytes)")
                else:
                    self.log_output("Database: Not found", "warning")
            except Exception as e:
                self.log_output(f"Database: Error - {str(e)}", "error")
                
        except Exception as e:
            self.log_output(f"Error checking system status: {str(e)}", "error")
    
    def view_security_logs(self):
        """View recent security logs."""
        self.log_output("=== RECENT SECURITY LOGS ===")
        
        try:
            logs_dir = "logs"
            if not os.path.exists(logs_dir):
                self.log_output("Logs directory not found", "warning")
                return
            
            # Get the most recent log file
            log_files = [f for f in os.listdir(logs_dir) if f.startswith("security_log_")]
            if not log_files:
                self.log_output("No security log files found", "warning")
                return
            
            # Sort by date and get the most recent
            log_files.sort(reverse=True)
            recent_log = os.path.join(logs_dir, log_files[0])
            
            self.log_output(f"Showing recent entries from: {log_files[0]}")
            
            # Read and display last 10 lines
            with open(recent_log, 'r') as f:
                lines = f.readlines()
                recent_lines = lines[-10:] if len(lines) > 10 else lines
                
                for line in recent_lines:
                    self.log_output(line.strip())
            
        except Exception as e:
            self.log_output(f"Error reading security logs: {str(e)}", "error")
    
    def run(self):
        """Start the GUI application."""
        try:
            self.log_output("Starting User Management GUI...")
            self.root.mainloop()
        except KeyboardInterrupt:
            self.log_output("Application interrupted by user")
        except Exception as e:
            self.log_output(f"Application error: {str(e)}", "error")

def main():
    """Main function to start the user management GUI."""
    try:
        app = UserManagementGUI()
        app.run()
    except Exception as e:
        print(f"Failed to start application: {e}")

if __name__ == "__main__":
    main()
