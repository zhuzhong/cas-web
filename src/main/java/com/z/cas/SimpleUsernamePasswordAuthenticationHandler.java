/**
 * 
 */
package com.z.cas;

import java.security.GeneralSecurityException;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;

import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.jasig.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;

/**只要用户名与密码相等，则认证通过
 * @author zhuzhong
 *
 */
public class SimpleUsernamePasswordAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler {

	/**
	 * {@inheritDoc}
	 **/
	@Override
	protected final HandlerResult authenticateUsernamePasswordInternal(final UsernamePasswordCredential credential)
			throws GeneralSecurityException, PreventedException {

		final String username = credential.getUsername();
		final String cachedPassword = credential.getPassword();

		if (cachedPassword == null) {
			logger.debug("{} was not found in the map.", username);
			throw new AccountNotFoundException(username + " not found in backing map.");
		}

		//final String encodedPassword = this.getPasswordEncoder().encode(credential.getPassword());
		if (!cachedPassword.equals(username)) {
			throw new FailedLoginException();
		}
		return createHandlerResult(credential, this.principalFactory.createPrincipal(username), null);
	}

}
