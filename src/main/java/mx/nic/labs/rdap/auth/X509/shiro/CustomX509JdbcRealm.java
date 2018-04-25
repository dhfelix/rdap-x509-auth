package mx.nic.labs.rdap.auth.X509.shiro;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.JdbcUtils;

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
public class CustomX509JdbcRealm extends JdbcRealm {

	/**
	 * This realm doesn't have logic to load user/roles permissions
	 */
	protected boolean permissionsLookupEnabled = false;

	public CustomX509JdbcRealm() {
		super();
		// NO SALT by default
		this.saltStyle = SaltStyle.NO_SALT;

		// Uncomment if a SALT is used and stored in database (the 'authenticationQuery'
		// must be set to return the salt of the password, eg. "SELECT rus_pass,
		// rus_pass_salt FROM rdap_user WHERE rus_name = ?").
		// this.saltStyle = SaltStyle.COLUMN;

		// Uncomment if a SALT is used and the salt will be loaded from wherever you
		// need. If the salt is the same as the username (default behavior) just
		// uncomment the line; if the salt is different then overwrite the method
		// "JdbcRealm.getSaltForUser(String)" and uncomment the line.
		// this.saltStyle = SaltStyle.EXTERNAL;
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
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		if (principals.fromRealm(getName()).isEmpty()) {
			return null;
		}
		return super.doGetAuthorizationInfo(principals);
	}

	@Override
	public boolean supports(AuthenticationToken token) {
		if (token != null)
			return token instanceof X509AuthToken;

		return false;
	}

	@Override
	protected Set<String> getRoleNamesForUser(Connection conn, String username) throws SQLException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		Set<String> roleNames = new LinkedHashSet<String>();

		try {
			ps = conn.prepareStatement(userRolesQuery);
			ps.setString(1, username);

			// Execute query
			rs = ps.executeQuery();
			while (rs.next()) {
				// Add the role to the list of names if it isn't null
				String roleName = rs.getString(1);
				if (roleName != null && !roleName.trim().isEmpty()) {
					roleNames.add(roleName.trim().toLowerCase());
				}
			}
		} finally {
			JdbcUtils.closeResultSet(rs);
			JdbcUtils.closeStatement(ps);
		}

		return roleNames;
	}

}