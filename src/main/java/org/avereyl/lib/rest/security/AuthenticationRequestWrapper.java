/**
 * 
 */
package  org.avereyl.lib.rest.security;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;

/**
 * 
 * This class wraps the servlet request to extract and store the request body.
 * The getInputStream method is overridden to return the stored request body and
 * so can be used several times.
 * 
 * @author guillaume
 * 
 */
public class AuthenticationRequestWrapper extends HttpServletRequestWrapper {

    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationRequestWrapper.class);

    /**
     * Body of the request saved as a string.
     */
    private final String requestBody;

    /**
     * Constructor.
     * 
     * @param request
     * @throws AuthenticationException
     */
    public AuthenticationRequestWrapper(HttpServletRequest request) throws AuthenticationException {

        super(request);

        // read the original payload into the xmlPayload variable
        StringBuilder stringBuilder = new StringBuilder();
        BufferedReader bufferedReader = null;
        try {
            // read the payload into the StringBuilder
            InputStream inputStream = request.getInputStream();
            if (inputStream != null) {
                bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                char[] charBuffer = new char[128];
                int bytesRead = -1;
                while ((bytesRead = bufferedReader.read(charBuffer)) > 0) {
                    stringBuilder.append(charBuffer, 0, bytesRead);
                }
            } else {
                // make an empty string since there is no payload.
                stringBuilder.append("");
            }
        } catch (IOException ex) {
            LOGGER.error("Error reading the request payload", ex);
            throw new AuthenticationServiceException("Error reading the request payload", ex);
        } finally {
            if (bufferedReader != null) {
                try {
                    bufferedReader.close();
                } catch (IOException iox) {
                	LOGGER.error("Error closing the buffer reader. {}", iox);
                }
            }
        }
        requestBody = stringBuilder.toString();
    }

    /**
     * Override of the getInputStream() method which returns an InputStream that
     * reads from the stored body request string instead of from the request's
     * actual InputStream.
     */
    @Override
    public ServletInputStream getInputStream() throws IOException {

        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(requestBody.getBytes());
        ServletInputStream inputStream = new ServletInputStream() {
            public int read() throws IOException {
                return byteArrayInputStream.read();
            }
        };
        return inputStream;
    }
}
