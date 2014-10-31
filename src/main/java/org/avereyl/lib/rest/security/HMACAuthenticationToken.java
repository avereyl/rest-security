/**
 * 
 */
package  org.avereyl.lib.rest.security;

import java.util.Collection;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * @author BILLAUDG
 * 
 */
public class HMACAuthenticationToken extends UsernamePasswordAuthenticationToken {

    /**
     * Serial UID.
     */
    private static final long serialVersionUID = -339839549364101793L;

    /**
     * 
     * @param principal
     * @param credentials
     */
    public HMACAuthenticationToken(Object principal, Object credentials) {
        super(principal, credentials);
    }

    /**
     * 
     * @param principal
     * @param credentials
     * @param authorities
     */
    public HMACAuthenticationToken(Object principal, Object credentials,
            Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }
}
