package mx.nic.labs.rdap.auth.X509.shiro;

import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.realm.text.TextConfigurationRealm;

import mx.nic.labs.rdap.auth.X509.shiro.token.X509AuthToken;

/**
 * Custom realm, extends from {@link JdbcRealm}, used to authenticate users.
 * This realm can be overwritten, deleted, altered to satisfy any other needs
 * (eg. another kind of authentication, load user/password from other place,
 * etc.). <br/>
 * <br/>
 * For something even more customized, you can see
 * <a href="https://shiro.apache.org/realm.html">Apache Shiro Realms</a> <br/>
 * <br/>
 * Based on <a href=
 * "https://mehmetceliksoy.wordpress.com/2015/06/28/shiro-jdbc-realm/">Shiro
 * JDBC Realm</a>
 */
public class CustomX509PropertiesRealm extends TextConfigurationRealm {

	/**
	 * This realm doesn't have logic to load user/roles permissions
	 */
	protected boolean permissionsLookupEnabled = false;

	public CustomX509PropertiesRealm() {
		super();
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

		X509AuthToken upToken = (X509AuthToken) token;
		String username = upToken.getUsername();

		// Null username is invalid
		if (username == null) {
			throw new AccountException("Null usernames are not allowed by this realm.");
		}

		return new SimpleAuthenticationInfo(username, upToken.getCredentials(), getName());
	}

	@Override
	public boolean supports(AuthenticationToken token) {
		if (token != null)
			return token instanceof X509AuthToken;

		return false;
	}


}