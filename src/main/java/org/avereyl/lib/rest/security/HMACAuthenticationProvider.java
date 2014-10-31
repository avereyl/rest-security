/**
 * 
 */
package  org.avereyl.lib.rest.security;

import java.text.MessageFormat;

import org.avereyl.lib.rest.security.helper.SecurityHelper;
import org.avereyl.lib.rest.security.service.UserSecurityService;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.Duration;
import org.joda.time.Minutes;
import org.joda.time.format.ISODateTimeFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * @author BILLAUDG
 * 
 */
public class HMACAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(HMACAuthenticationProvider.class);
    
    /**
     * Maximum default period between the given timestamp and now (in minutes) to consider the timestamp as valid.
     */
    private static final Integer DEFAULT_VALIDITY = 5;
    
    /**
     * 
     */
    @Value("${security.timestamp.validity}")
    private Integer maxNumberOfMinutesForValidity;

    /**
     * Service to retrieve user by key.
     */
    private UserSecurityService userSecurityService;

    /**
     * This is the method which actually performs the check to see whether the
     * user is indeed the correct user
     * 
     * @param userDetails
     * @param authentication
     * @throws AuthenticationException
     */
    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails,
            UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        // here we check if the details provided by the user actually stack up.

        // Get Credentials out of the Token...
        HMACAuthenticationToken token = (HMACAuthenticationToken) authentication;
        if (token != null) {
            if (authentication.getCredentials() == null) {
                LOGGER.debug("Authentication failed: no credentials provided");
                throw new BadCredentialsException(messages.getMessage(
                        "AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
            }

            HMACCredentials credentials = (HMACCredentials) authentication.getCredentials();
            // Checking...
            // Check given timestamp
            boolean validTimestamp = checkTimestampValidity(credentials);
            // Calculate the new hash from given credentials
            boolean validHash = checkHMACValidity(userDetails, credentials);
            if (!validHash || !validTimestamp) {
                LOGGER.debug("Authentication failed: hash does not match stored values or timestamp no longer valid");
                throw new BadCredentialsException(messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials",
                 "Bad credentials"));
            } else {
                LOGGER.debug("Authentication succeed");
            }

        } else {
            LOGGER.debug("Authentication failed: token null");
            throw new AuthenticationCredentialsNotFoundException(MessageFormat.format(
                    "Expected Authentication Token object of type {0}, but instead received {1}",
                    HMACAuthenticationToken.class.getSimpleName(), authentication.getClass().getSimpleName()));
        }
    }


    /**
     * 
     * @param username
     *            This is the "login" of the user.
     * 
     * @param authentication
     *            The authentication request, which subclasses <em>may</em> need
     *            to perform a binding-based retrieval of the
     *            <code>UserDetails</code>
     * 
     * @return the user information (never <code>null</code> - instead an
     *         exception should the thrown)
     * 
     * @throws AuthenticationException
     *             if the credentials could not be validated (generally a
     *             <code>BadCredentialsException</code>, an
     *             <code>AuthenticationServiceException</code> or
     *             <code>UsernameNotFoundException</code>)
     */
    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        LOGGER.info("Loading user by username = {}", username);
        UserDetails loadedUser;
        try {
            loadedUser = userSecurityService.loadUserByUsername(username);
            LOGGER.info("Loaded user = {}", loadedUser);
        } catch (UsernameNotFoundException notFound) {
            throw notFound;
        } catch (Exception repositoryProblem) {
            throw new AuthenticationServiceException(repositoryProblem.getMessage(), repositoryProblem);
        }
        if (loadedUser == null) {
            throw new AuthenticationServiceException(
                    "UserSecurityServiceImpl returned null, which is an interface contract violation");
        }
        return loadedUser;
    }

    /**
     * Check that the given credentials match with the user.
     * @param userDetails User
     * @param credentials Credentials
     * @return boolean whether the hash is OK or NOK.
     */
    private boolean checkHMACValidity(UserDetails userDetails, HMACCredentials credentials) {
        String expectedHash = "";
        String givenHash = credentials.getHash();
        String secretKey = userDetails.getPassword();
        // check hash
        expectedHash = SecurityHelper.computeHMAC(credentials, secretKey);
        LOGGER.info("'{}' hashed with '{}' gives '{}'",credentials.toString(), secretKey, expectedHash);
        // hash equality checking
        return expectedHash.equals(givenHash);
    }

    /**
     * 
     * @param credentials
     * @return
     */
    private boolean checkTimestampValidity(HMACCredentials credentials) {
        boolean result = true;
        try {
            DateTime now = new DateTime(DateTimeZone.UTC);
            DateTime givenTimestamp = DateTime.parse(credentials.getTimestamp(), ISODateTimeFormat.ordinalDateTime());
            Duration duration = new Duration(givenTimestamp, now);
            LOGGER.debug("Time between now and given timestamp : {}", duration.toString());
            int nbMinutes = (maxNumberOfMinutesForValidity == null) ? DEFAULT_VALIDITY : maxNumberOfMinutesForValidity.intValue();
            result &= (Minutes.minutes(nbMinutes).compareTo(duration.toStandardMinutes()) >= 0);
        } catch (IllegalArgumentException iae) {
            LOGGER.error("IllegalArgumentException when parsing date. {}", iae);
            result = false;
        }
        return result;
    }
    
    /**
     * @return the userSecurityService
     */
    public UserSecurityService getUserSecurityService() {
        return userSecurityService;
    }

    /**
     * @param userSecurityService
     *            the userSecurityService to set
     */
    public void setUserSecurityService(UserSecurityService userSecurityService) {
        this.userSecurityService = userSecurityService;
    }

}
