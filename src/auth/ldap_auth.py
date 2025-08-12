"""
LDAP Authentication Module
"""

from typing import Tuple, Dict, Any, Optional
from ldap3 import Server, Connection, ALL, NTLM, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, Tls
from ldap3.core.exceptions import LDAPException
import secrets
import string
import ssl

from ..core.config import Config
from ..core.base import BaseAuthenticator
from ..utils.security_utils import SecurityUtils


class LDAPAuthenticator(BaseAuthenticator):
    """LDAP authentication against Active Directory or LDAP server."""
    
    def __init__(self, config=None):
        if config is None:
            config = Config()
            
        self.server_uri = config.LDAP_SERVER
        self.use_ssl = getattr(config, 'LDAP_USE_SSL', True)
        self.ssl_port = getattr(config, 'LDAP_SSL_PORT', 636)
        self.verify_ssl = getattr(config, 'LDAP_VERIFY_SSL', False)
        self.base_dn = config.LDAP_BASE_DN
        self.admin_group = config.LDAP_ADMIN_GROUP
        self.operator_group = config.LDAP_OPERATOR_GROUP
        self.user_group = config.LDAP_USER_GROUP
        
        # Organizational Units for different user types
        self.admin_ou = getattr(config, 'LDAP_ADMIN_OU', f"CN=Users,DC={self.base_dn.replace('.', ',DC=')}")
        self.operator_ou = getattr(config, 'LDAP_OPERATOR_OU', f"CN=Users,DC={self.base_dn.replace('.', ',DC=')}")
        self.user_ou = getattr(config, 'LDAP_USER_OU', f"CN=Users,DC={self.base_dn.replace('.', ',DC=')}")
        
        # Admin credentials for user creation operations
        self.admin_user = getattr(config, 'LDAP_ADMIN_USER', 'administrator')
        self.admin_password = getattr(config, 'LDAP_ADMIN_PASSWORD', '')
        self.admin_dn = getattr(config, 'LDAP_ADMIN_DN', f"CN=administrator,CN=Users,DC={self.base_dn.replace('.', ',DC=')}")
        
    def is_available(self) -> bool:
        """Check if LDAP authentication is available."""
        try:
            server = Server(self.server_uri, get_info=ALL)
            # Try to connect to test availability
            conn = Connection(server)
            conn.bind()
            conn.unbind()
            return True
        except Exception:
            return False
    
    def authenticate(self, credentials: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Authenticate user against LDAP server.
        
        Args:
            credentials: Dictionary with 'username' and 'password' keys
            
        Returns:
            Tuple of (success, username/error_message)
        """
        username = credentials.get('username')
        password = credentials.get('password')
        
        if not username or not password:
            return False, "Username and password required"
        
        try:
            # Extract username from domain\username format if provided
            if '\\' in username:
                domain, username_only = username.split('\\', 1)
            else:
                username_only = username
                domain = self.base_dn
            
            # Create server connection
            server = Server(self.server_uri, get_info=ALL)
            
            # Try different authentication formats to avoid MD4 hash issues
            auth_formats = [
                f"{username_only}@{self.base_dn}",  # UPN format
                f"{username_only}",  # Simple username
                f"{domain}\\{username_only}"  # Domain\username format
            ]
            
            conn = None
            auth_success = False
            
            # Try each authentication format
            for auth_user in auth_formats:
                try:
                    # Use SIMPLE authentication instead of NTLM to avoid MD4 issues
                    conn = Connection(
                        server, 
                        user=auth_user, 
                        password=password, 
                        auto_bind=True,
                        authentication='SIMPLE'  # Use SIMPLE instead of NTLM
                    )
                    
                    if conn and conn.bound:
                        auth_success = True
                        break
                        
                except Exception as e:
                    # Try next format if this one fails
                    continue
            
            # If SIMPLE auth fails, try with no explicit authentication type
            if not auth_success:
                for auth_user in auth_formats:
                    try:
                        conn = Connection(server, user=auth_user, password=password)
                        if conn.bind():
                            auth_success = True
                            break
                    except Exception:
                        continue
            
            if not auth_success or not conn or not conn.bound:
                SecurityUtils.log_security_event("LDAP_AUTH_FAILED", f"LDAP authentication failed for user: {username_only}")
                return False, "Invalid credentials"
            
            # Prepare search base - convert domain to DN format
            if '.' in self.base_dn:
                # Convert domain.com to DC=domain,DC=com
                domain_parts = self.base_dn.split('.')
                search_base = ','.join([f"DC={part}" for part in domain_parts])
            else:
                search_base = f"DC={self.base_dn}"
            
            # Get user info and group memberships
            search_filter = f"(sAMAccountName={username_only})"
            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=['cn', 'mail', 'memberOf', 'displayName']
            )
            
            if not conn.entries:
                conn.unbind()
                return False, "User not found"
            
            user_entry = conn.entries[0]
            user_groups = user_entry.memberOf.values if hasattr(user_entry, 'memberOf') else []
            
            # Determine user role based on group membership
            role = self._determine_user_role(user_groups)
            
            conn.unbind()
            
            SecurityUtils.log_security_event("LDAP_AUTH_SUCCESS", 
                                           f"LDAP authentication successful for user: {username_only}, role: {role}")
            
            return True, {
                "username": username_only, 
                "role": role, 
                "email": str(user_entry.mail) if hasattr(user_entry, 'mail') else None,
                "display_name": str(user_entry.displayName) if hasattr(user_entry, 'displayName') else username_only
            }
            
        except LDAPException as e:
            SecurityUtils.log_security_event("LDAP_AUTH_ERROR", f"LDAP authentication error for user {username}: {str(e)}")
            return False, f"LDAP error: {str(e)}"
        except Exception as e:
            SecurityUtils.log_security_event("LDAP_AUTH_ERROR", f"Authentication error for user {username}: {str(e)}")
            return False, f"Authentication error: {str(e)}"
    
    def _determine_user_role(self, user_groups: list) -> str:
        """Determine user role based on group membership."""
        group_names = [group.split(',')[0].split('=')[1] for group in user_groups]
        
        if self.admin_group in group_names:
            return "admin"
        elif self.operator_group in group_names:
            return "operator"
        elif self.user_group in group_names:
            return "user"
        else:
            return "guest"  # Default role for users not in specific groups
    
    def get_user_info(self, username: str) -> Optional[Dict[str, Any]]:
        """Get detailed user information from LDAP."""
        try:
            server = Server(self.server_uri, get_info=ALL)
            conn = Connection(server)
            conn.bind()
            
            search_filter = f"(sAMAccountName={username})"
            conn.search(
                search_base=f"DC={self.base_dn.replace('.', ',DC=')}",
                search_filter=search_filter,
                attributes=['cn', 'mail', 'memberOf', 'displayName', 'department']
            )
            
            if conn.entries:
                user_entry = conn.entries[0]
                user_info = {
                    'username': username,
                    'full_name': str(user_entry.cn) if hasattr(user_entry, 'cn') else username,
                    'display_name': str(user_entry.displayName) if hasattr(user_entry, 'displayName') else username,
                    'email': str(user_entry.mail) if hasattr(user_entry, 'mail') else None,
                    'department': str(user_entry.department) if hasattr(user_entry, 'department') else None,
                    'groups': user_entry.memberOf.values if hasattr(user_entry, 'memberOf') else [],
                    'role': self._determine_user_role(user_entry.memberOf.values if hasattr(user_entry, 'memberOf') else [])
                }
                
                conn.unbind()
                return user_info
            
            conn.unbind()
            return None
            
        except Exception as e:
            print(f"Error getting user info: {e}")
            return None

    def user_exists(self, username: str) -> bool:
        """Check if a user exists in LDAP."""
        try:
            server = Server(self.server_uri, get_info=ALL)
            conn = Connection(server)
            conn.bind()
            
            # Prepare search base - convert domain to DN format
            if '.' in self.base_dn:
                domain_parts = self.base_dn.split('.')
                search_base = ','.join([f"DC={part}" for part in domain_parts])
            else:
                search_base = f"DC={self.base_dn}"
            
            search_filter = f"(sAMAccountName={username})"
            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=['cn']
            )
            
            user_exists = len(conn.entries) > 0
            conn.unbind()
            return user_exists
            
        except Exception as e:
            print(f"Error checking if user exists: {e}")
            return False

    def create_user(self, username: str, password: str, first_name: str = "", 
                   last_name: str = "", email: str = "", role: str = "user") -> Tuple[bool, str]:
        """
        Create a new user in LDAP.
        
        Args:
            username: Username for the new user
            password: Password for the new user
            first_name: First name of the user
            last_name: Last name of the user
            email: Email address of the user
            role: Role/group for the user (admin, operator, user)
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Check if user already exists
            if self.user_exists(username):
                return False, f"User '{username}' already exists"
            
            # Validate password policy first
            valid, message = self.validate_password_policy(password)
            if not valid:
                return False, f"Password policy violation: {message}"
            
            # Create SSL server for secure password operations
            server = self._create_ssl_server()
            
            # Use administrative credentials to create user
            if not self.admin_password:
                return False, "LDAP admin credentials not configured. Please set LDAP_ADMIN_PASSWORD in config."
            
            # Try different admin authentication methods
            admin_conn = None
            auth_methods = [
                # Method 1: Use admin DN directly
                (self.admin_dn, self.admin_password, 'SIMPLE'),
                # Method 2: Use domain\username format
                (f"{self.base_dn.split('.')[0]}\\{self.admin_user}", self.admin_password, 'SIMPLE'),
                # Method 3: Use UPN format
                (f"{self.admin_user}@{self.base_dn}", self.admin_password, 'SIMPLE'),
                # Method 4: Just username
                (self.admin_user, self.admin_password, 'SIMPLE')
            ]
            
            # Try the most reliable authentication method first
            admin_conn = None
            
            # Primary authentication attempts with detailed error handling
            auth_attempts = [
                # Method 1: Domain\Username format (most common for AD)
                {
                    'user': f"{self.base_dn.split('.')[0]}\\{self.admin_user}",
                    'auth': 'SIMPLE',
                    'description': 'Domain\\Username format'
                },
                # Method 2: UPN format
                {
                    'user': f"{self.admin_user}@{self.base_dn}",
                    'auth': 'SIMPLE', 
                    'description': 'UPN format'
                },
                # Method 3: Distinguished Name
                {
                    'user': self.admin_dn,
                    'auth': 'SIMPLE',
                    'description': 'Distinguished Name'
                },
                # Method 4: Simple username
                {
                    'user': self.admin_user,
                    'auth': 'SIMPLE',
                    'description': 'Simple username'
                },
                # Method 5: No explicit authentication (let ldap3 decide)
                {
                    'user': f"{self.base_dn.split('.')[0]}\\{self.admin_user}",
                    'auth': None,
                    'description': 'Auto authentication'
                }
            ]
            
            last_error = None
            for attempt in auth_attempts:
                try:
                    if attempt['auth']:
                        admin_conn = Connection(
                            server, 
                            user=attempt['user'], 
                            password=self.admin_password,
                            authentication=attempt['auth'],
                            auto_bind=True
                        )
                    else:
                        admin_conn = Connection(
                            server, 
                            user=attempt['user'], 
                            password=self.admin_password,
                            auto_bind=True
                        )
                    
                    if admin_conn and admin_conn.bound:
                        print(f"✅ Admin authentication successful using {attempt['description']}: {attempt['user']}")
                        break
                    else:
                        admin_conn = None
                        
                except Exception as e:
                    last_error = str(e)
                    print(f"❌ {attempt['description']} failed: {last_error}")
                    admin_conn = None
                    continue
            
            if not admin_conn or not admin_conn.bound:
                return False, f"Failed to authenticate with LDAP admin credentials. Last error: {last_error}. Check LDAP_ADMIN_USER and LDAP_ADMIN_PASSWORD in config."

            # Prepare search base - convert domain to DN format
            if '.' in self.base_dn:
                domain_parts = self.base_dn.split('.')
                search_base = ','.join([f"DC={part}" for part in domain_parts])
            else:
                search_base = f"DC={self.base_dn}"
            
            # Create user DN - use full name if available, otherwise username
            if first_name and last_name:
                cn_name = f"{first_name} {last_name}"
            elif first_name:
                cn_name = first_name
            else:
                cn_name = username
                
            # Get the appropriate OU based on user role
            user_ou = self._get_user_ou(role, search_base)
            user_dn = f"CN={cn_name},{user_ou}"
            print(f"Creating user DN: {user_dn} in OU: {user_ou}")
            
            # Ensure the OU exists before creating user
            if not self._ensure_ou_exists(user_ou, admin_conn):
                # If OU creation fails, fall back to default Users container
                user_dn = f"CN={cn_name},CN={user_ou},{search_base}"
                print(f"Warning: Could not create/access OU {user_ou}, using default Users container")
            
            # User attributes - create enabled account directly with password
            full_name = f"{first_name} {last_name}".strip() or username
            display_name = full_name
            
            # Encode password for unicodePwd attribute (Active Directory method)
            password_encoded = f'"{password}"'.encode('utf-16le')
            
            attributes = {
                'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
                'cn': full_name,
                'sAMAccountName': username,
                'userPrincipalName': f"{username}@{self.base_dn}",
                'displayName': display_name,
                'givenName': first_name,
                'sn': last_name or username,
                'userAccountControl': 512,  # Normal account, enabled
                'unicodePwd': password_encoded,  # Set password directly using AD-specific attribute
                'pwdLastSet': -1,  # Password set by admin, no change required
                'accountExpires': 0,  # Account never expires
            }
            
            if email:
                attributes['mail'] = email
            
            # Create user with password and enabled status in one operation
            success = admin_conn.add(user_dn, attributes=attributes)
            
            if success:
                try:
                    # Add user to appropriate group based on role using working logic from test.py
                    group_dn = self._find_group_dn_dynamically(role, search_base, admin_conn)
                    if group_dn:
                        group_name = group_dn.split(',')[0].split('=')[1]  # Extract group name from DN
                        
                        # Ensure the group exists before trying to add user
                        if self._ensure_group_exists(group_dn, group_name, admin_conn):
                            # Add user to group with retry logic (same method as working test.py)
                            group_success = self._add_user_to_group_with_retry(admin_conn, user_dn, group_dn, group_name)
                            if not group_success:
                                print(f"Warning: Could not add user to group {group_dn}, but user was created successfully")
                        else:
                            print(f"Warning: Could not create/access group {group_dn}, user not added to any group")
                    else:
                        print(f"Warning: No group mapping found for role '{role}', user not added to any group")
                    
                    # TODO: uncomment this line 
                    # disable useraccount
                    """admin_conn.modify(
                        user_dn,
                        {'userAccountControl': [(MODIFY_REPLACE, [546])]}  # Normal account, disabled
                    )"""
                    
                    admin_conn.unbind()
                    SecurityUtils.log_security_event("LDAP_USER_CREATED", 
                                                   f"Created LDAP user: {username}, role: {role}")
                    return True, f"User '{username}' created successfully with role '{role}'."
                    
                except Exception as group_error:
                    # User created successfully, just group assignment failed
                    admin_conn.unbind()
                    return True, f"User '{username}' created successfully, but group assignment failed: {str(group_error)}. Please assign group manually."
            else:
                # Primary method failed, try fallback approach
                admin_conn.unbind()
                
                # Fallback: Create account without password first, then set password
                return self._create_user_fallback(username, password, first_name, last_name, email, role)
            
        except LDAPException as e:
            # If direct creation fails, try fallback method
            try:
                return self._create_user_fallback(username, password, first_name, last_name, email, role)
            except:
                error_details = {
                    'error': str(e),
                    'server_info': getattr(e, 'result', 'No result info'),
                    'description': getattr(e, 'description', 'No description')
                }
                return False, f"LDAP error creating user: {error_details}"
        except Exception as e:
            # If direct creation fails, try fallback method
            try:
                return self._create_user_fallback(username, password, first_name, last_name, email, role)
            except:
                return False, f"Error creating user: {str(e)}"

    def _create_user_fallback(self, username: str, password: str, first_name: str = "", 
                             last_name: str = "", email: str = "", role: str = "user") -> Tuple[bool, str]:
        """Fallback method: Create disabled account first, then set password and enable."""
        try:
            # Create SSL server for secure password operations
            server = self._create_ssl_server()
            
            # Authenticate admin connection
            admin_conn = None
            auth_methods = [
                (self.admin_dn, self.admin_password, 'SIMPLE'),
                (f"{self.base_dn.split('.')[0]}\\{self.admin_user}", self.admin_password, 'SIMPLE'),
                (f"{self.admin_user}@{self.base_dn}", self.admin_password, 'SIMPLE'),
                (self.admin_user, self.admin_password, 'SIMPLE')
            ]
            
            for admin_user_format, admin_pass, auth_type in auth_methods:
                try:
                    admin_conn = Connection(
                        server, 
                        user=admin_user_format, 
                        password=admin_pass,
                        authentication=auth_type,
                        auto_bind=True
                    )
                    if admin_conn and admin_conn.bound:
                        break
                except Exception:
                    admin_conn = None
                    continue
            
            if not admin_conn or not admin_conn.bound:
                return False, "Failed to authenticate with LDAP admin credentials."
            
            # Prepare DN and attributes
            if '.' in self.base_dn:
                domain_parts = self.base_dn.split('.')
                search_base = ','.join([f"DC={part}" for part in domain_parts])
            else:
                search_base = f"DC={self.base_dn}"
            
            # Create user DN
            cn_name = f"{first_name} {last_name}".strip() or username
            user_ou = self._get_user_ou(role, search_base)
            
            if not self._ensure_ou_exists(user_ou, admin_conn):
                user_dn = f"CN={cn_name},CN=Users,{search_base}"
            else:
                user_dn = f"CN={cn_name},{user_ou}"
            
            # Create disabled account first
            full_name = f"{first_name} {last_name}".strip() or username
            
            attributes = {
                'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
                'cn': full_name,
                'sAMAccountName': username,
                'userPrincipalName': f"{username}@{self.base_dn}",
                'displayName': full_name,
                'givenName': first_name or username,
                'sn': last_name or username,
                'userAccountControl': 546,  # Disabled account initially
                'accountExpires': 0,  # Account never expires
            }
            
            if email:
                attributes['mail'] = email
            
            # Create user account
            success = admin_conn.add(user_dn, attributes=attributes)
            
            if not success:
                admin_conn.unbind()
                return False, f"Fallback method failed to create user: {admin_conn.result}"
            
            try:
                # Set password using compatible method
                password_success = self._set_password_compatible(admin_conn, user_dn, password)
                
                if not password_success:
                    admin_conn.delete(user_dn)
                    admin_conn.unbind()
                    return False, "Failed to set password using fallback method"
                
                # Enable account and set password flags
                enable_success = admin_conn.modify(user_dn, {
                    'userAccountControl': [(MODIFY_REPLACE, [512])],  # Normal account, enabled
                    'pwdLastSet': [(MODIFY_REPLACE, [-1])]  # Password set by admin, no change required
                })
                
                if not enable_success:
                    admin_conn.unbind()
                    return True, f"User '{username}' created with password, but account is disabled. Enable manually in AD."
                
                # Add user to appropriate group using improved logic
                group_dn = self._find_group_dn_dynamically(role, search_base, admin_conn)
                if group_dn:
                    group_name = group_dn.split(',')[0].split('=')[1]  # Extract group name from DN
                    
                    # Ensure the group exists before trying to add user
                    if self._ensure_group_exists(group_dn, group_name, admin_conn):
                        # Add user to group with retry logic
                        group_success = self._add_user_to_group_with_retry(admin_conn, user_dn, group_dn, group_name)
                        if not group_success:
                            print(f"Warning: Could not add user to group {group_dn} in fallback method")
                    else:
                        print(f"Warning: Could not create/access group {group_dn} in fallback method")
                else:
                    print(f"Warning: Could not find group DN for role '{role}', user not added to any group")
                
                admin_conn.unbind()
                SecurityUtils.log_security_event("LDAP_USER_CREATED", 
                                               f"Created LDAP user: {username}, role: {role} (fallback method)")
                
                return True, f"User '{username}' created successfully with role '{role}' using fallback method. Account is enabled and ready to use."
                
            except Exception as password_error:
                try:
                    admin_conn.delete(user_dn)
                except:
                    pass
                admin_conn.unbind()
                return False, f"Fallback method failed to configure password: {str(password_error)}"
                
        except Exception as e:
            return False, f"Fallback method error: {str(e)}"

    def delete_user(self, username: str) -> Tuple[bool, str]:
        """
        Delete a user from LDAP.
        
        Args:
            username: Username to delete
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Create SSL server for secure operations
            server = self._create_ssl_server()
            
            # Use administrative credentials to delete user
            if not self.admin_password:
                return False, "Admin credentials not configured for user deletion"
            
            # Try different admin authentication methods
            admin_conn = None
            auth_methods = [
                (self.admin_dn, self.admin_password, 'SIMPLE'),
                (f"{self.base_dn.split('.')[0]}\\{self.admin_user}", self.admin_password, 'SIMPLE'),
                (f"{self.admin_user}@{self.base_dn}", self.admin_password, 'SIMPLE'),
                (self.admin_user, self.admin_password, 'SIMPLE')
            ]
            
            for admin_user_format, admin_pass, auth_type in auth_methods:
                try:
                    admin_conn = Connection(
                        server, 
                        user=admin_user_format, 
                        password=admin_pass,
                        authentication=auth_type,
                        auto_bind=True
                    )
                    if admin_conn and admin_conn.bound:
                        print(f"✅ Admin authentication successful using: {admin_user_format}")
                        break
                except Exception as auth_error:
                    print(f"❌ Admin auth failed with {admin_user_format}: {auth_error}")
                    admin_conn = None
                    continue
            
            if not admin_conn or not admin_conn.bound:
                return False, "Failed to authenticate with LDAP admin credentials for deletion"
            
            # Find user DN
            if '.' in self.base_dn:
                domain_parts = self.base_dn.split('.')
                search_base = ','.join([f"DC={part}" for part in domain_parts])
            else:
                search_base = f"DC={self.base_dn}"
            
            search_filter = f"(sAMAccountName={username})"
            admin_conn.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=['cn']  # We just need to confirm the user exists
            )
            
            if not admin_conn.entries:
                admin_conn.unbind()
                return False, f"User '{username}' not found in LDAP"
            
            user_entry = admin_conn.entries[0]
            user_dn = str(user_entry.entry_dn)
            
            print(f"🔍 Found user to delete: {user_dn}")
            
            # Delete user account
            success = admin_conn.delete(user_dn)
            
            if success:
                admin_conn.unbind()
                SecurityUtils.log_security_event("LDAP_USER_DELETED", f"Deleted LDAP user: {username}")
                print(f"✅ User '{username}' deleted successfully from LDAP")
                return True, f"User '{username}' deleted successfully from LDAP"
            else:
                admin_conn.unbind()
                error_msg = f"Failed to delete user from LDAP: {admin_conn.result}"
                print(f"❌ {error_msg}")
                return False, error_msg
                
        except LDAPException as e:
            return False, f"LDAP error deleting user: {str(e)}"
        except Exception as e:
            return False, f"Error deleting user: {str(e)}"

    def _get_group_dn(self, role: str, search_base: str) -> Optional[str]:
        """Get the DN for a group based on role."""
        group_mapping = {
            'admin': self.admin_group,
            'operator': self.operator_group,
            'user': self.user_group
        }
        
        group_name = group_mapping.get(role, self.user_group)
        if group_name:
            # Based on your AD structure, groups are in OU=SecuritySystem
            return f"CN={group_name},OU=SecuritySystem,{search_base}"
        return None

    def _ensure_group_exists(self, group_dn: str, group_name: str, admin_conn: Connection) -> bool:
        """Ensure the group exists, create it if it doesn't."""
        try:
            # Check if group exists using search like in your working test.py
            admin_conn.search(
                search_base=group_dn,
                search_filter="(objectClass=group)",
                search_scope='BASE',
                attributes=['cn']
            )
            
            # If we found it, it exists
            if admin_conn.entries:
                print(f"✅ Group {group_name} exists at {group_dn}")
                return True
            
            # Group doesn't exist, try to create it
            print(f"📝 Creating group: {group_name}")
            
            # Create the group
            attributes = {
                'objectClass': ['top', 'group'],
                'cn': group_name,
                'sAMAccountName': group_name,
                'groupType': -2147483646,  # Global security group
                'description': f'Security System group for {group_name} users'
            }
            
            success = admin_conn.add(group_dn, attributes=attributes)
            if success:
                print(f"✅ Successfully created group: {group_name}")
                return True
            else:
                print(f"❌ Failed to create group {group_name}: {admin_conn.result}")
                return False
            
        except Exception as e:
            print(f"❌ Error checking/creating group {group_dn}: {e}")
            return False

    def _add_user_to_group_with_retry(self, admin_conn: Connection, user_dn: str, group_dn: str, group_name: str) -> bool:
        """Add user to group with multiple retry methods - based on working test.py logic."""
        try:
            # Method 1: Standard group member modification (same as your working test.py)
            group_success = admin_conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
            
            if group_success:
                print(f"✅ Successfully added user to group {group_name}")
                return True
            else:
                print(f"❌ Failed to add user to group {group_name}: {admin_conn.result}")
                
                # Method 2: Try using the Microsoft extension
                try:
                    result = admin_conn.extend.microsoft.add_members_to_groups([user_dn], [group_dn])
                    if result:
                        print(f"✅ Successfully added user to group {group_name} using Microsoft extension")
                        return True
                except Exception as ext_error:
                    print(f"❌ Microsoft extension also failed: {ext_error}")
                
                # Method 3: Check if user is already in the group
                admin_conn.search(
                    search_base=group_dn,
                    search_filter="(objectClass=group)",
                    attributes=['member']
                )
                
                if admin_conn.entries and hasattr(admin_conn.entries[0], 'member'):
                    members = admin_conn.entries[0].member.values if admin_conn.entries[0].member else []
                    if user_dn in members:
                        print(f"ℹ️  User is already a member of group {group_name}")
                        return True
                
                return False
                
        except Exception as e:
            print(f"❌ Error adding user to group {group_name}: {e}")
            return False

    def _find_group_dn_dynamically(self, role: str, search_base: str, admin_conn: Connection) -> Optional[str]:
        """Dynamically find group DN like in your working test.py"""
        group_mapping = {
            'admin': self.admin_group,
            'operator': self.operator_group,
            'user': self.user_group
        }
        
        group_name = group_mapping.get(role, self.user_group)
        if not group_name:
            return None
        
        try:
            # Search for the group anywhere in the domain (like your test.py)
            admin_conn.search(
                search_base,
                f'(&(objectClass=group)(cn={group_name}))',
                attributes=['distinguishedName', 'cn']
            )
            
            if admin_conn.entries:
                actual_group_dn = str(admin_conn.entries[0].distinguishedName)
                print(f"Found {group_name} group: {actual_group_dn}")
                return actual_group_dn
            else:
                print(f"❌ {group_name} group not found")
                return None
                
        except Exception as e:
            print(f"❌ Error searching for group {group_name}: {e}")
            return None

    def _get_user_ou(self, role: str, search_base: str) -> str:
        """Get the appropriate OU for a user based on their role."""
        ou_mapping = {
            'admin': self.admin_ou,
            'operator': self.operator_ou,
            'user': self.user_ou
        }
        
        # Return the OU for the role, or default to user OU
        return ou_mapping.get(role, self.user_ou)

    def _ensure_ou_exists(self, ou_dn: str, admin_conn: Connection) -> bool:
        """Ensure the OU exists, create it if it doesn't."""
        try:
            # Check if OU exists
            admin_conn.search(
                search_base=ou_dn,
                search_filter="(objectClass=organizationalUnit)",
                search_scope='BASE',
                attributes=['cn']
            )
            
            # If we found it, it exists
            if admin_conn.entries:
                return True
            
            # OU doesn't exist, try to create it
            # Parse the OU DN to get components
            dn_parts = ou_dn.split(',')
            if not dn_parts:
                return False
                
            # Get the OU name from the first component
            ou_part = dn_parts[0]
            if not ou_part.startswith('OU='):
                return False
                
            ou_name = ou_part[3:]  # Remove 'OU=' prefix
            parent_dn = ','.join(dn_parts[1:])  # Everything after the first OU
            
            # Create the OU
            attributes = {
                'objectClass': ['top', 'organizationalUnit'],
                'ou': ou_name,
                'name': ou_name,
                'description': f'Security System OU for {ou_name}'
            }
            
            success = admin_conn.add(ou_dn, attributes=attributes)
            return success
            
        except Exception as e:
            print(f"Error checking/creating OU {ou_dn}: {e}")
            return False

    def generate_temporary_password(self, length: int = 12) -> str:
        """Generate a secure temporary password for new users."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password

    def _create_ssl_server(self) -> Server:
        """Create an SSL-enabled LDAP server for password operations."""
        try:
            if not self.use_ssl:
                # If SSL is disabled in config, return regular server
                print(f"Using regular LDAP: {self.server_uri}")
                return Server(self.server_uri, get_info=ALL)
            
            # Configure TLS settings based on config - working configuration
            validate_mode = ssl.CERT_REQUIRED if self.verify_ssl else ssl.CERT_NONE
            tls_configuration = Tls(
                validate=validate_mode, 
                version=ssl.PROTOCOL_TLS,
                ca_certs_file=None,
                valid_names=None
            )
            
            # Handle LDAPS URI properly
            if self.server_uri.startswith('ldaps://'):
                ssl_uri = self.server_uri
                if not ':636' in ssl_uri:
                    ssl_uri += ':636'
            elif self.server_uri.startswith('ldap://'):
                # Replace ldap:// with ldaps:// and update port if needed
                base_uri = self.server_uri.replace('ldap://', '').split(':')[0]
                ssl_uri = f"ldaps://{base_uri}:{self.ssl_port}"
            else:
                # Assume it's just hostname/IP
                ssl_uri = f"ldaps://{self.server_uri}:{self.ssl_port}"
            
            # Create server with working SSL configuration
            server = Server(ssl_uri, use_ssl=True, tls=tls_configuration, get_info=ALL)
            print(f"Created SSL LDAP server: {ssl_uri}")
            return server
            
        except Exception as e:
            print(f"Failed to create SSL server: {e}")
            # Fallback to regular server
            print("Falling back to non-SSL server for password operations")
            fallback_uri = self.server_uri.replace('ldaps://', 'ldap://').replace(':636', ':389')
            return Server(fallback_uri, get_info=ALL)

    def _ensure_secure_connection(self, conn: Connection) -> bool:
        """Ensure the connection is secure for password operations."""
        try:
            # If connection is not already using SSL, try to start TLS
            if not conn.server.ssl and not conn.server.tls:
                success = conn.start_tls()
                if not success:
                    print("Warning: Could not establish secure TLS connection for password operations")
                    return False
            return True
        except Exception as e:
            print(f"Failed to establish secure connection: {e}")
            return False

    def _set_password_compatible(self, conn: Connection, user_dn: str, password: str) -> bool:
        """Try multiple methods to set password in order of compatibility with SSL requirement."""
        # Ensure we have a secure connection for password operations
        if not self._ensure_secure_connection(conn):
            print("Warning: Proceeding with password setting on insecure connection")
        
        methods = [
            # Method 1: Microsoft extension (most reliable for AD)
            lambda: conn.extend.microsoft.modify_password(user_dn, password),
            
            # Method 2: Direct unicodePwd attribute (AD specific)
            lambda: conn.modify(user_dn, {
                'unicodePwd': [(MODIFY_REPLACE, [f'"{password}"'.encode('utf-16le')])]
            }),
            
            # Method 3: Standard userPassword (LDAP generic)
            lambda: conn.modify(user_dn, {
                'userPassword': [(MODIFY_REPLACE, [password.encode('utf-8')])]
            })
        ]
        
        for i, method in enumerate(methods, 1):
            try:
                result = method()
                if result:
                    print(f"Password set successfully using method {i}")
                    return True
                else:
                    print(f"Password method {i} returned False")
            except Exception as e:
                print(f"Password method {i} failed: {e}")
                continue
        
        return False

    def validate_password_policy(self, password: str) -> Tuple[bool, str]:
        """Validate password against common AD policies."""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if len(password) > 128:
            return False, "Password cannot exceed 128 characters"
        
        # Check complexity requirements
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        complexity_count = sum([has_upper, has_lower, has_digit, has_special])
        if complexity_count < 3:
            return False, "Password must contain at least 3 of: uppercase, lowercase, digit, special character"
        
        return True, "Password meets policy requirements"
