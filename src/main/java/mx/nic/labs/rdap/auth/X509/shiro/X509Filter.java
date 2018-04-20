package mx.nic.labs.rdap.auth.X509.shiro;

import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.PrincipalUtil;

import mx.nic.labs.rdap.auth.X509.shiro.token.X509AuthToken;

/**
 * Custom Filter, extends from {@link AuthenticatingFilterRealm}, used to
 * authenticate users.
 */
public class X509Filter extends AuthenticatingFilter {

	/**
	 * The name that is displayed during the challenge process of authentication,
	 * defauls to <code>application</code> and can be overridden by the
	 * {@link #setApplicationName(String) setApplicationName} method.
	 */
	private String applicationName = "application";

	private static Logger logger = Logger.getLogger(X509Filter.class.getName());

	@Override
	protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
		Object certObj = request.getAttribute("javax.servlet.request.X509Certificate");
		if (certObj == null) {
			logger.log(Level.SEVERE, "null javax.servlet.request.X509Certificate");
			return new X509AuthToken();
		}
		String subject = null;
		X509Certificate[] certs = (X509Certificate[]) certObj;
		X509Certificate cert = certs[0];

		
		X500Name instance = X500Name.getInstance(PrincipalUtil.getSubjectX509Principal(cert));
		RDN[] rdNs = instance.getRDNs(BCStyle.CN);
		subject = rdNs[0].getFirst().getValue().toString();

		boolean rememberMe = isRememberMe(request);
		String host = getHost(request);

		return new X509AuthToken(subject, host, rememberMe, certs[0]);
	}

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		// Access restricted, try the login
		if (!executeLogin(request, response)) {
			((HttpServletResponse) response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return false;
		}
		return true;
	}

	/**
	 * Returns the name to use in the ServletResponse's
	 * <b><code>WWW-Authenticate</code></b> header.
	 * <p/>
	 * Per RFC 2617, this name name is displayed to the end user when they are asked
	 * to authenticate. Unless overridden by the {@link #setApplicationName(String)
	 * setApplicationName(String)} method, the default value is 'application'.
	 * <p/>
	 * Please see {@link #setApplicationName(String) setApplicationName(String)} for
	 * an example of how this functions.
	 *
	 * @return the name to use in the ServletResponse's 'WWW-Authenticate' header.
	 */
	public String getApplicationName() {
		return applicationName;
	}

	/**
	 * Sets the name to use in the ServletResponse's
	 * <b><code>WWW-Authenticate</code></b> header.
	 * <p/>
	 * Per RFC 2617, this name name is displayed to the end user when they are asked
	 * to authenticate. Unless overridden by this method, the default value is
	 * &quot;application&quot;
	 * <p/>
	 * For example, setting this property to the value
	 * <b><code>Awesome Webapp</code></b> will result in the following header:
	 * <p/>
	 * <code>WWW-Authenticate: Basic realm=&quot;<b>Awesome Webapp</b>&quot;</code>
	 * <p/>
	 * Side note: As you can see from the header text, the HTTP Basic specification
	 * calls this the authentication 'realm', but we call this the 'applicationName'
	 * instead to avoid confusion with Shiro's Realm constructs.
	 *
	 * @param applicationName
	 *            the name to use in the ServletResponse's 'WWW-Authenticate'
	 *            header.
	 */
	public void setApplicationName(String applicationName) {
		this.applicationName = applicationName;
	}

	@Override
	protected final boolean isLoginRequest(ServletRequest request, ServletResponse response) {
		return request.getAttribute("javax.servlet.request.X509Certificate") != null;
	}

}