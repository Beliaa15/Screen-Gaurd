"""
LDAP Authentication Module
"""

from typing import Tuple, Dict, Any, Optional
from ldap3 import Server, Connection, ALL, NTLM, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException
import secrets
import string

from ..core.config import Config
from ..core.base import BaseAuthenticator
from ..utils.security_utils import SecurityUtils


class LDAPAuthenticator(BaseAuthenticator):
    """LDAP authentication against Active Directory or LDAP server."""
    
    def __init__(self, config=None):
        if config is None:
            config = Config()
            
        self.server_uri = config.LDAP_SERVER
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
            
            server = Server(self.server_uri, get_info=ALL)
            
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
                        
                except Exception as e:
                    admin_conn = None
                    continue
            
            if not admin_conn or not admin_conn.bound:
                return False, f"Failed to authenticate with LDAP admin credentials. Check LDAP_ADMIN_USER and LDAP_ADMIN_PASSWORD in config."
            
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
            
            # Ensure the OU exists before creating user
            if not self._ensure_ou_exists(user_ou, admin_conn):
                # If OU creation fails, fall back to default Users container
                user_dn = f"CN={cn_name},CN=Users,{search_base}"
                print(f"Warning: Could not create/access OU {user_ou}, using default Users container")
            
            # User attributes
            full_name = f"{first_name} {last_name}".strip() or username
            display_name = full_name
            
            attributes = {
                'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
                'cn': full_name,
                'sAMAccountName': username,
                'userPrincipalName': f"{username}@{self.base_dn}",
                'displayName': display_name,
                'givenName': first_name,
                'sn': last_name or username,
                'userAccountControl': 546,  # Disabled account initially (will enable after setting password)
            }
            
            if email:
                attributes['mail'] = email
            
            # Add user to LDAP (disabled initially)
            success = admin_conn.add(user_dn, attributes=attributes)
            
            if success:
                try:
                    # Set password first
                    admin_conn.extend.microsoft.modify_password(user_dn, password)

                    # Enable the account after password is set
                    admin_conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})
                    
                    # Add user to appropriate group based on role
                    group_dn = self._get_group_dn(role, search_base)
                    if group_dn:
                        admin_conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
                    
                    admin_conn.unbind()
                    SecurityUtils.log_security_event("LDAP_USER_CREATED", 
                                                   f"Created LDAP user: {username}, role: {role}")
                    return True, f"User '{username}' created successfully in OU=SecuritySystem with role '{role}'"
                    
                except Exception as password_error:
                    # If password setting fails, try to delete the user to clean up
                    try:
                        admin_conn.delete(user_dn)
                    except:
                        pass
                    admin_conn.unbind()
                    return False, f"Failed to set password for user: {str(password_error)}"
            else:
                admin_conn.unbind()
                error_info = {
                    'result_code': admin_conn.result.get('result', 'Unknown'),
                    'description': admin_conn.result.get('description', 'Unknown'),
                    'message': admin_conn.result.get('message', 'No message'),
                    'dn': admin_conn.result.get('dn', 'No DN')
                }
                return False, f"Failed to create user: {admin_conn.result}. Error details: {error_info}"
            
        except LDAPException as e:
            error_details = {
                'error': str(e),
                'server_info': getattr(e, 'result', 'No result info'),
                'description': getattr(e, 'description', 'No description')
            }
            return False, f"LDAP error creating user: {error_details}"
        except Exception as e:
            return False, f"Error creating user: {str(e)}"

    def delete_user(self, username: str) -> Tuple[bool, str]:
        """
        Delete a user from LDAP.
        
        Args:
            username: Username to delete
            
        Returns:
            Tuple of (success, message)
        """
        try:
            if not self.user_exists(username):
                return False, f"User '{username}' does not exist"
            
            server = Server(self.server_uri, get_info=ALL)
            conn = Connection(server)
            
            if not conn.bind():
                return False, "Failed to connect to LDAP server with admin privileges"
            
            # Find user DN
            if '.' in self.base_dn:
                domain_parts = self.base_dn.split('.')
                search_base = ','.join([f"DC={part}" for part in domain_parts])
            else:
                search_base = f"DC={self.base_dn}"
            
            search_filter = f"(sAMAccountName={username})"
            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=['dn']
            )
            
            if not conn.entries:
                conn.unbind()
                return False, f"User '{username}' not found"
            
            user_dn = str(conn.entries[0].entry_dn)
            
            # Delete user
            success = conn.delete(user_dn)
            
            if success:
                conn.unbind()
                SecurityUtils.log_security_event("LDAP_USER_DELETED", f"Deleted LDAP user: {username}")
                return True, f"User '{username}' deleted successfully"
            else:
                conn.unbind()
                return False, f"Failed to delete user: {conn.result}"
                
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
            return f"CN={group_name},CN=Groups,{search_base}"
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
