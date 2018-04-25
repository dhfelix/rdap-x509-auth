package mx.nic.labs.rdap.auth.X509.shiro;

import java.util.Collections;

import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import mx.nic.labs.rdap.auth.X509.shiro.token.X509AuthToken;

/**
 * Custom realm, extends from {@link AuthenticatingRealm}, used to authenticate
 * users based on X509 certs.
 */
public class CustomX509SecurityRealm extends AuthorizingRealm {

	/**
	 * This realm doesn't have logic to load user/roles permissions
	 */
	protected boolean permissionsLookupEnabled = false;

	public CustomX509SecurityRealm() {
		super();
	}

	@Override
	public boolean supports(AuthenticationToken token) {
		if (token != null)
			return token instanceof X509AuthToken;

		return false;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
			throws AuthenticationException {
		
		X509AuthToken upToken = (X509AuthToken) token;
		String username = upToken.getUsername();

		// Null username is invalid
		if (username == null) {
			throw new AccountException("Null usernames are not allowed by this realm.");
		}

		return new SimpleAuthenticationInfo(username, upToken.getCredentials(), getName());
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		if (principals.fromRealm(getName()).isEmpty()) {
			return null;
		}
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(Collections.emptySet());
		info.setStringPermissions(null);
		return info;
	}

}