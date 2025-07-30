"""
LDAP Authentication Module
"""

from typing import Tuple, Dict, Any, Optional
from ldap3 import Server, Connection, ALL, NTLM, MODIFY_ADD, MODIFY_DELETE
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
            # This would need to be configured with proper admin credentials
            conn = Connection(server)
            
            # For this example, we'll use anonymous bind or would need admin credentials
            # In production, you'd need proper LDAP admin credentials
            if not conn.bind():
                return False, "Failed to connect to LDAP server with admin privileges"
            
            # Prepare search base - convert domain to DN format
            if '.' in self.base_dn:
                domain_parts = self.base_dn.split('.')
                search_base = ','.join([f"DC={part}" for part in domain_parts])
            else:
                search_base = f"DC={self.base_dn}"
            
            # Create user DN
            user_dn = f"CN={first_name} {last_name},CN=Users,{search_base}"
            
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
                'userAccountControl': 512,  # Normal account, enabled
            }
            
            if email:
                attributes['mail'] = email
            
            # Add user to LDAP
            success = conn.add(user_dn, attributes=attributes)
            
            if success:
                # Set password
                conn.extend.microsoft.modify_password(user_dn, password)
                
                # Add user to appropriate group based on role
                group_dn = self._get_group_dn(role, search_base)
                if group_dn:
                    conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
                
                conn.unbind()
                SecurityUtils.log_security_event("LDAP_USER_CREATED", 
                                               f"Created LDAP user: {username}, role: {role}")
                return True, f"User '{username}' created successfully"
            else:
                conn.unbind()
                return False, f"Failed to create user: {conn.result}"
            
        except LDAPException as e:
            return False, f"LDAP error creating user: {str(e)}"
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

    def generate_temporary_password(self, length: int = 12) -> str:
        """Generate a secure temporary password for new users."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password
