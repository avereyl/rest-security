/**
 * 
 */
package  org.avereyl.lib.rest.security;

import org.avereyl.lib.rest.config.RestTestConfig;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author BILLAUDG
 * 
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = RestTestConfig.class)
public class HMACAuthenticationFilterTest {

    /**
     * The filter to test.
     */
    private HMACAuthenticationFilter filter = new HMACAuthenticationFilter("/");

    /**
     * This method challenges the conversion of a String into a map of String.
     */
    @Test
    public void testGetUsernameAndSignatureFromAuthorizationHeader() {
        // given
        String username = "Guillaume";
        String signature = "d06580e4c786ac587f310b9fea5fc40c66d86449";
        StringBuilder sb = new StringBuilder();
        sb.append(HMACAuthenticationFilter.AUTHORIZATION_PREFIX);
        sb.append(username);
        sb.append(HMACAuthenticationFilter.AUTHORIZATION_HEADER_SEPARATOR);
        sb.append(signature);
        String authorizationHeader = sb.toString();
        // when
        String[] credentials = filter.getUsernameAndSignatureFromAuthorizationHeader(authorizationHeader);
        // then
        Assert.assertNotNull("The map should not be null.", credentials);
        Assert.assertEquals("The map size should be 3", 3, credentials.length);
        Assert.assertEquals("Username should match with the one given.", username, credentials[1]);
        Assert.assertEquals("Signature should match with the one given.", signature, credentials[2]);
    }
}
