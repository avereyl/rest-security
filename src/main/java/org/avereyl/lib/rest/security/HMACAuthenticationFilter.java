/**
 * 
 */
package  org.avereyl.lib.rest.security;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.event.AuthorizationFailureEvent;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.StringUtils;

/**
 * Filter responsible for authentication process.
 * @author BILLAUDG
 * 
 */
public class HMACAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(HMACAuthenticationFilter.class);

    /**
     * Name of the "Authorization" header.
     */
    public static final String AUTHORIZATION_HEADER_NAME = "Authorization";
    /**
     * Prefix of the "Authorization" header value.
     */
    public static final String AUTHORIZATION_PREFIX = "BSPV ";
    /**
     * Name of the "date" key in Authorization header.
     */
    public static final String X_BSPV_DATE_HEADER_NAME = "x-bspv-date";
    /**
     * Name of the "Content-Type" header.
     */
    private static final String CONTENT_TYPE_HEADER_NAME = "Content-Type";

    /**
     * Separator in Authorization header.
     */
    public static final String AUTHORIZATION_HEADER_SEPARATOR = ":";

    /**
     * @param defaultFilterProcessesUrl
     *            the default value for <tt>filterProcessesUrl</tt>.
     */
    protected HMACAuthenticationFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.web.authentication.
     * AbstractAuthenticationProcessingFilter
     * #attemptAuthentication(javax.servlet.http.HttpServletRequest,
     * javax.servlet.http.HttpServletResponse)
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        HMACCredentials credentials = getCredentialsFromRequest(request);
        LOGGER.debug("###{}###", credentials.toString());
        AbstractAuthenticationToken authRequest = createAuthenticationToken(credentials.getUsername(), credentials);
        // Allow subclasses to set the "details" property.
        setDetails(request, authRequest);
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    /**
     * 
     * @param request
     * @return
     * @throws UnsupportedEncodingException
     */
    private HMACCredentials getCredentialsFromRequest(HttpServletRequest request) {

        String authorizationHeader = getHeaderValue(request, AUTHORIZATION_HEADER_NAME);
        String[] authorizationCredentials = getUsernameAndSignatureFromAuthorizationHeader(authorizationHeader);
        String username = authorizationCredentials[1];
        String signature = authorizationCredentials[2];
        String timestamp = obtainXBSPVDateValue(request);
        String contentMD5 = obtainContentMD5Value(request);
        String contentType = obtainContentTypeValue(request);
        String method = request.getMethod();
        String url = request.getRequestURL().toString();

        return new HMACCredentials(username, contentMD5, contentType, timestamp, method, url, signature);
    }

    /**
     * Extract Authorization type, User's name and Signature from {@link AuthorizationFailureEvent} header.
     * @param authorizationHeader The given Authorization HTTP header.
     * @return An array of 3 strings (Authorization type, User's name, Signature)
     */
    public String[] getUsernameAndSignatureFromAuthorizationHeader(String authorizationHeader) {
        String[] credentials = { "", "", "" };
        if (!StringUtils.isEmpty(authorizationHeader)) {
            try {
                credentials[0] = authorizationHeader.substring(0, AUTHORIZATION_PREFIX.length());
                String[] usernameSignature = authorizationHeader.substring(AUTHORIZATION_PREFIX.length()).split(
                        AUTHORIZATION_HEADER_SEPARATOR);
                credentials[1] = usernameSignature[0];
                credentials[2] = usernameSignature[1];
            } catch (IndexOutOfBoundsException ioobe) {
                LOGGER.error("Malformed Authorization header, should be 'BSPV username:signature', given '{}'. {}",
                        authorizationHeader, ioobe);
            }
        }
        return credentials;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.web.authentication.
     * AbstractAuthenticationProcessingFilter
     * #successfulAuthentication(javax.servlet.http.HttpServletRequest,
     * javax.servlet.http.HttpServletResponse, javax.servlet.FilterChain,
     * org.springframework.security.core.Authentication)
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            FilterChain chain, Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
        chain.doFilter(request, response);
    }

    /**
     * Method to get header value from the request.
     * 
     * @param request
     *            The request
     * @param headerParameterName
     *            Name of the header
     * @return
     */
    private String getHeaderValue(HttpServletRequest request, String headerParameterName) {
        String headerValue = "";
        if (request.getHeader(headerParameterName) != null) {
            headerValue = request.getHeader(headerParameterName);
        }
        LOGGER.debug("Header '{}' : '{}'", headerParameterName, headerValue);
        return headerValue;
    }

    /**
     * Method to get the "Content-Type" header value.
     * 
     * @param request
     *            the request
     * @return The value of the header if exists, empty string otherwise
     */
    private String obtainContentTypeValue(HttpServletRequest request) {
        return getHeaderValue(request, CONTENT_TYPE_HEADER_NAME);
    }

    /**
     * Method to get the "x-bspv-date" header value.
     * 
     * @param request
     *            the request
     * @return The value of the header if exists, empty string otherwise
     */
    private String obtainXBSPVDateValue(HttpServletRequest request) {
        return getHeaderValue(request, X_BSPV_DATE_HEADER_NAME);
    }

    /**
     * Method to calculate the "Content-MD5" header value.
     * 
     * @param request
     *            the request
     * @return The value of the header if exists, empty string otherwise
     */
    private String obtainContentMD5Value(HttpServletRequest request) {
        String md5 = "";
        try {
            md5 = DigestUtils.md5Hex(request.getInputStream());
        } catch (IOException e) {
            LOGGER.error("Failed to compute MD5 hash of the servlet content. {}", e);
        }
        return md5;
    }

    /**
     * Provided so that subclasses may configure what is put into the
     * authentication request's details property.
     * 
     * @param request
     *            that an authentication request is being created for
     * @param authRequest
     *            the authentication request object that should have its details
     *            set
     */
    protected void setDetails(HttpServletRequest request, AbstractAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }

    /**
     * 
     * @param username
     * @param hmacCredentials
     * @return
     */
    private AbstractAuthenticationToken createAuthenticationToken(String username, HMACCredentials hmacCredentials) {
        return new HMACAuthenticationToken(username, hmacCredentials);
    }

    /**
     * Because we require the API client to send credentials with every request,
     * we must authenticate on every request
     */
    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        return true;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.web.authentication.
     * AbstractAuthenticationProcessingFilter
     * #doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse,
     * javax.servlet.FilterChain)
     */
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException,
            ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        LOGGER.debug("Request is to process authentication");

        AuthenticationRequestWrapper authenticationRequestWrapper;
        try {
            authenticationRequestWrapper = new AuthenticationRequestWrapper(request);
        } catch (AuthenticationException ex) {
            LOGGER.warn("Unable to wrap the request", ex);
            throw new ServletException("Unable to wrap the request", ex);
        }

        Authentication authResult;

        try {
            authResult = attemptAuthentication(authenticationRequestWrapper, response);
            if (authResult == null) {
                // return immediately as subclass has indicated that it hasn't
                // completed authentication
                return;
            }
        } catch (InternalAuthenticationServiceException failed) {
            LOGGER.error("An internal error occurred while trying to authenticate the user.", failed);
            unsuccessfulAuthentication(authenticationRequestWrapper, response, failed);
            return;
        } catch (AuthenticationException failed) {
            // Authentication failed
            unsuccessfulAuthentication(authenticationRequestWrapper, response, failed);
            return;
        }

        // Authentication success
        successfulAuthentication(authenticationRequestWrapper, response, chain, authResult);
    }

}
