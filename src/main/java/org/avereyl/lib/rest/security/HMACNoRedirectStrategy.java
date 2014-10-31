/**
 * 
 */
package  org.avereyl.lib.rest.security;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.RedirectStrategy;

/**
 * @author BILLAUDG
 * 
 */
public class HMACNoRedirectStrategy implements RedirectStrategy {

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.springframework.security.web.RedirectStrategy#sendRedirect(javax.
     * servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse,
     * java.lang.String)
     */
    public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url) throws IOException {
        // No need to redirect !
    }

}