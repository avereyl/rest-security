/**
 * 
 */
package  org.avereyl.lib.rest;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.MediaType;

/**
 * @author BILLAUDG
 * 
 */
public final class Constant {

    /**
     * Private constructor.
     */
    private Constant() {
    }

    /**
     * Greetings message.
     */
    public static final String HELLO_WORLD = "Hello World !";

    /**
     * Commons HTTP headers.
     */
    public static final Map<String, String> COMMON_HEADERS = new HashMap<String, String>();
    static {
        COMMON_HEADERS.put("Content-Language", "fr-FR");
        COMMON_HEADERS.put("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        COMMON_HEADERS.put("API-Version", "1.0");
    }
    
    
}
