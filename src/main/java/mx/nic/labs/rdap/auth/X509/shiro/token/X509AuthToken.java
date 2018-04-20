package mx.nic.labs.rdap.auth.X509.shiro.token;

import java.security.cert.X509Certificate;

import org.apache.shiro.authc.HostAuthenticationToken;
import org.apache.shiro.authc.RememberMeAuthenticationToken;

public class X509AuthToken implements HostAuthenticationToken, RememberMeAuthenticationToken {

	/**
	 * generated with eclipse
	 */
	private static final long serialVersionUID = -1166473787163981913L;

	private String username;

	private boolean rememberMe;

	private String host;

	private X509Certificate x509;

	public X509AuthToken() {
		// Empty
	}
	
	public X509AuthToken(String subject, String host, boolean rememberMe, X509Certificate x509) {
		this.username = subject;
		this.host = host;
		this.rememberMe = rememberMe;
		this.x509 = x509;
	}

	@Override
	public Object getPrincipal() {
		return getUsername();
	}

	public String getUsername() {
		return username;
	}

	@Override
	public Object getCredentials() {
		return x509;
	}

	@Override
	public boolean isRememberMe() {
		return rememberMe;
	}

	@Override
	public String getHost() {
		return host;
	}

}
