/**
 * 
 */
package  org.avereyl.lib.rest.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Constant class.
 * @author BILLAUDG
 *
 */
public final class Constant {

    /**
     * Common salt.
     */
    public final static String SALT = "%@2G452FLjkdsg524d";
    /**
     * Default HMAC algorithm.
     */
    public static final String SHA1_HMAC_ALGORITHM = "HmacSHA1";
    /**
     * Default hashing algorithm.
     */
    public static final String DEFAULT_HASH_ALGORITHM = "SHA-1";
    /**
     * MD5 hashing algorithm.
     */
    public static final String MD5_HASH_ALGORITHM = "MD5";
    /**
     * Encoding used for encryption.
     */
    public static final String ENCODING_FOR_ENCRYPTION = "UTF-8";
    
    /**
     * Admin authority.
     */
    public static final GrantedAuthority ROLE_ADMIN = new SimpleGrantedAuthority("ROLE_ADMIN");
    
    /**
     * User authority.
     */
    public static final GrantedAuthority ROLE_USER = new SimpleGrantedAuthority("ROLE_USER");
    
    
    
    
    /**
     * Private constructor.
     */
    private Constant() {
    }
}
