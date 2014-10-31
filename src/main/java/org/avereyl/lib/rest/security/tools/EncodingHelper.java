/**
 * 
 */
package  org.avereyl.lib.rest.security.tools;

import org.avereyl.lib.rest.security.Constant;
import org.avereyl.lib.rest.security.helper.SecurityHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encoding helper class, gives the secret key for the given user and password.
 * @author BILLAUDG
 * 
 */
public class EncodingHelper {

    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(EncodingHelper.class);

    /**
     * Users.
     */
    private static String[][] USERS = { { "Guillaume", "Rantanplan" }, { "Alice", "AlicePassword123" },
            { "Bob", "BobPassword123" } };
    
    /**
     * Private constructor.
     */
    private EncodingHelper() {
    	// All methods of this helper class should be accessed in a static way.
    }

    /**
     * @param args
     */
    public static void main(String[] args) {
        for (String[] user : USERS) {
            String username = user[0];
            String password = user[1];
            String secretKey = SecurityHelper.sha1Hex(SecurityHelper.sha1Hex(username + password)
                    + Constant.SALT);
            LOGGER.info("---------------------------------------------------------");
            LOGGER.info("username:{}", username);
            LOGGER.info("password:{}", password);
            LOGGER.info("secretKey:{}", secretKey);
        }
    }

}
