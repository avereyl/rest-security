/**
 * 
 */
package  org.avereyl.lib.rest.security;

/**
 * @author BILLAUDG
 * 
 */
public final class HMACCredentials {

    /**
     * Name of the user.
     */
    private String username;
    /**
     * MD5 hash of the request content.
     */
    private String contentMD5;
    /**
     * Content-Type header of the request.
     */
    private String contentType;
    /**
     * Date of the request creation.
     */
    private String timestamp;
    /**
     * HTTP method.
     */
    private String method;
    /**
     * URL.
     */
    private String url;
    /**
     * Hash.
     */
    private String hash;

    /**
     * @param username
     * @param contentMD5
     * @param timestamp
     * @param method
     * @param url
     * @param salt
     * @param hash
     */
    public HMACCredentials(String username, String contentMD5, String contentType, String timestamp, String method, String url, String hash) {
        super();
        this.username = username;
        this.contentMD5 = contentMD5;
        this.contentType = contentType;
        this.timestamp = timestamp;
        this.method = method;
        this.url = url;
        this.hash = hash;
    }

    /**
     * @return the hash
     */
    public String getHash() {
        return hash;
    }

    /**
     * @return the username
     */
    public String getUsername() {
        return username;
    }

    /**
     * @return the contentMD5
     */
    public String getContentMD5() {
        return contentMD5;
    }

    /**
     * @return the contentType
     */
    public final String getContentType() {
        return contentType;
    }

    /**
     * @param contentType the contentType to set
     */
    public final void setContentType(String contentType) {
        this.contentType = contentType;
    }

    /**
     * @return the timestamp
     */
    public String getTimestamp() {
        return timestamp;
    }

    /**
     * @return the method
     */
    public String getMethod() {
        return method;
    }

    /**
     * @return the url
     */
    public String getUrl() {
        return url;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "HMACCredentials [username=" + username + ", contentMD5=" + contentMD5 + ", contentType=" + contentType
                + ", timestamp=" + timestamp + ", method=" + method + ", url=" + url + ", hash=" + hash + "]";
    }

}
