/**
 * 
 */
package  org.avereyl.lib.rest.security.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.avereyl.lib.rest.security.Constant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * @author BILLAUDG
 * 
 */
@Service(value = "dumbUserSecurityService")
public class DumbUserSecurityServiceImpl implements UserSecurityService, InitializingBean {

    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DumbUserSecurityServiceImpl.class);
    
    /**
     * Map of users (Username -> User details)
     */
    private final Map<String, UserDetails> users = new HashMap<String, UserDetails>();
    /**
     * List of authorities for admin users.
     */
    private final List<GrantedAuthority> adminAuthorities = new ArrayList<GrantedAuthority>();
    /**
     * List of authorities for simple users.
     */
    private final List<GrantedAuthority> userAuthorities = new ArrayList<GrantedAuthority>();
    /**
     * List of authorities for authenticated users.
     */
    private final List<GrantedAuthority> emptyAuthorities = new ArrayList<GrantedAuthority>();

    @Value("${security.user.dumb.admin.username}")
    private String adminUsername;

    @Value("${security.user.dumb.admin.secretkey}")
    private String adminSecretKey;

    @Value("${security.user.dumb.simple.username}")
    private String simpleUsername;

    @Value("${security.user.dumb.simple.secretkey}")
    private String simpleSecretKey;

    @Value("${security.user.dumb.authentified.username}")
    private String authentifiedUsername;

    @Value("${security.user.dumb.authentified.secretkey}")
    private String authentifiedSecretKey;

    /**
     * Constructor.
     */
    public DumbUserSecurityServiceImpl() {
        super();
        // init authorities
        adminAuthorities.add(Constant.ROLE_ADMIN);
        adminAuthorities.add(Constant.ROLE_USER);
        userAuthorities.add(Constant.ROLE_USER);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.core.userdetails.UserDetailsService#
     * loadUserByUsername(java.lang.String)
     */
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (users.containsKey(username)) {
            return users.get(username);
        }
        throw new UsernameNotFoundException("No user found for username " + username);
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
     */
    public void afterPropertiesSet() throws Exception {
        // init users map
        users.put(adminUsername, new User(adminUsername, adminSecretKey, adminAuthorities));
        users.put(simpleUsername, new User(simpleUsername, simpleSecretKey, userAuthorities));
        users.put(authentifiedUsername, new User(authentifiedUsername, authentifiedSecretKey, emptyAuthorities));
        LOGGER.info("Users declared !");
    }

}
