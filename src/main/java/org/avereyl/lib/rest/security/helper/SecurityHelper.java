/**
 * 
 */
package  org.avereyl.lib.rest.security.helper;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.avereyl.lib.rest.security.Constant;
import org.avereyl.lib.rest.security.HMACCredentials;
import org.springframework.util.StringUtils;

/**
 * @author BILLAUDG
 * 
 */
public class SecurityHelper extends DigestUtils {

    /**
     * Sign data with given key and SHA1 algorithm.
     * @param data Data to sign
     * @param key Key
     * @return SHA1 signature
     */
    public static String hmacSha1Hex(String data, String key) {
        return hmacHex(data, key, Constant.SHA1_HMAC_ALGORITHM);
    }

    /**
     * Sign data with given key and given algorithm.
     * @param data Data to sign
     * @param key Key
     * @param signatureMethod Name of the algorithm to be used to make the signature
     * @return
     */
    public static String hmacHex(String data, String key, String signatureMethod) {
        String signature = "";
        byte[] hmacData = null;
        if (!StringUtils.isEmpty(data)) {
            try {
                // secretKey
                SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(Constant.ENCODING_FOR_ENCRYPTION),
                        signatureMethod);
                Mac mac = Mac.getInstance(signatureMethod);
                mac.init(secretKey);
                hmacData = mac.doFinal(data.getBytes(Constant.ENCODING_FOR_ENCRYPTION));
                signature = Hex.encodeHexString(hmacData);
            } catch (InvalidKeyException ike) {
                // key is stored and should be always OK
                throw new RuntimeException("Invalid Key while encrypting.", ike);
            } catch (UnsupportedEncodingException e) {
                // encoding is written is source code so should always be OK
                throw new RuntimeException("Unsupported Encoding while encrypting.", e);
            } catch (NoSuchAlgorithmException nsae) {
                // algorithm is written is source code so should always be OK
                throw new IllegalArgumentException("No such algorithm [" + signatureMethod + "]", nsae);
            }
        } else {
            throw new IllegalArgumentException("The string to encode should not be empty.");
        }
        return signature;
    }
    
    /**
     * Compute the HMAC for given credentials and user secret.
     * @param credentials Credentials
     * @param secretKey The secret key
     * @return the computed mac.
     */
    public static final String computeHMAC(HMACCredentials credentials, String secretKey) {
        StringBuilder sb = new StringBuilder();
        sb.append(credentials.getMethod());
        sb.append(credentials.getUrl());
        sb.append(credentials.getUsername());
        sb.append(credentials.getTimestamp());
        sb.append(credentials.getContentMD5());
        sb.append(credentials.getContentType());
        sb.append(Constant.SALT);
        return SecurityHelper.hmacSha1Hex(sb.toString(), secretKey);
    }

}
