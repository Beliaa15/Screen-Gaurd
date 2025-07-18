from security_utils import LDAPAuthenticator
from config import Config

ldap = LDAPAuthenticator(Config())
print(ldap.authenticate("secadmin", "Aa12345@"))