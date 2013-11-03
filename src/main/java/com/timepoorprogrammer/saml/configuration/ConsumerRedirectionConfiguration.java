package com.timepoorprogrammer.saml.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;

/**
 * Assertion consumer redirection configuration details bound together by the
 * customerCode (the internal Northgate code for the identity provider) and
 * the serviceCode (the internal Northgate code for the service provider such
 * as MyView).  So this provides the right redirection and cookie details for
 * a given application for a SAML assertion that comes in for a given customer.
 *
 * @author Jim Ball
 */
public class ConsumerRedirectionConfiguration implements Serializable {
    private static final long serialVersionUID = 2252517761842432641L;
    private static final Logger log = LoggerFactory.getLogger(ConsumerRedirectionConfiguration.class);
    private String customerCode;
    private String serviceCode;
    private String baseUrl;
    private String serviceUrl;
    private String errorUrl;
    private String sessionCookieDomain;
    private String sessionCookiePath;
    private String sessionCookieName;
    private boolean sessionCookieSecureFlag;
    private boolean sessionCookieHttpOnlyFlag;
    private String arrowPointCookieDomain;
    private String arrowPointCookiePath;
    private String arrowPointCookieName;
    private String arrowPointCookieValue;
    private boolean arrowPointCookieSecureFlag;
    private boolean arrowPointCookieHttpOnlyFlag;

    /**
     * Extract all the required settings for a consumer's customer specific redirection settings
     * and throw if any are missing.
     *
     * @param properties   properties
     * @param customerCode identity provider internal Northgate customer code
     * @param serviceCode  service provider internal Northgate code
     */
    public ConsumerRedirectionConfiguration(final ConfigurationProperties properties, final String customerCode, final String serviceCode) {
        if (properties == null || customerCode == null || serviceCode == null) {
            throw new IllegalArgumentException("Configuration properties and/or customerCode and/or serviceCode missing");
        }
        final String combinedIds = customerCode + "." + serviceCode;
        // The customerCode is how we identify our customers, and this can be used as the customer
        // code throughout the rest of the Northgate application domain.  We pass this customer code onto
        // the remote applications so they can do any "bespoke" customer specific stuff they might already
        // do for the customer on the basis of this code if needed.
        this.customerCode = customerCode;
        this.serviceCode = serviceCode;
        this.baseUrl = properties.getParameter("saml", combinedIds, "baseUrl");
        this.serviceUrl = properties.getParameter("saml", combinedIds, "serviceUrl");
        this.errorUrl = properties.getParameter("saml", combinedIds, "errorUrl");
        this.sessionCookieDomain = properties.getParameter("saml", combinedIds, "sessionCookieDomain");
        this.sessionCookiePath = properties.getParameter("saml", combinedIds, "sessionCookiePath");
        this.sessionCookieName = properties.getParameter("saml", combinedIds, "sessionCookieName");
        this.sessionCookieSecureFlag = "true".equalsIgnoreCase(properties.getParameter("saml", combinedIds, "sessionCookieSecureFlag"));
        this.sessionCookieHttpOnlyFlag = "true".equalsIgnoreCase(properties.getParameter("saml", combinedIds, "sessionCookieHttpOnlyFlag"));

        this.arrowPointCookieDomain = properties.getParameter("saml", combinedIds, "arrowPointCookieDomain");
        this.arrowPointCookiePath = properties.getParameter("saml", combinedIds, "arrowPointCookiePath");
        this.arrowPointCookieName = properties.getParameter("saml", combinedIds, "arrowPointCookieName");
        this.arrowPointCookieValue = properties.getParameter("saml", combinedIds, "arrowPointCookieValue");
        this.arrowPointCookieSecureFlag = "true".equalsIgnoreCase(properties.getParameter("saml", combinedIds, "arrowPointCookieSecureFlag"));
        this.arrowPointCookieHttpOnlyFlag = "true".equalsIgnoreCase(properties.getParameter("saml", combinedIds, "arrowPointCookieHttpOnlyFlag"));

        if (baseUrl == null || serviceUrl == null || errorUrl == null || sessionCookieDomain == null
                || sessionCookiePath == null || sessionCookieName == null || arrowPointCookieDomain == null
                || arrowPointCookiePath == null || arrowPointCookieName == null || arrowPointCookieValue == null) {
            final String errorMessage = "Key parameter values are missing, check your setup for all the parameters needed to define a producer";
            log.error(errorMessage);
            throw new RuntimeException(errorMessage);
        }
    }

    /**
     * Customer code.
     *
     * @return internal Northgate customer code
     */
    public String getCustomerCode() {
        return customerCode;
    }

    public void setCustomerCode(String customerCode) {
        this.customerCode = customerCode;
    }

    /**
     * Service code
     *
     * @return internal Northgate service code
     */
    public String getServiceCode() {
        return serviceCode;
    }

    public void setServiceCode(String serviceCode) {
        this.serviceCode = serviceCode;
    }

    /**
     * Path to the backdoor of an application
     *
     * @return path to application backdoor
     */
    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    /**
     * Path to authoriser service at remote application
     *
     * @return path to authoriser service
     */
    public String getServiceUrl() {
        return serviceUrl;
    }

    public void setServiceUrl(String serviceUrl) {
        this.serviceUrl = serviceUrl;
    }

    /**
     * Path to customer specific error page
     *
     * @return Path to customer specific error page
     */
    public String getErrorUrl() {
        return errorUrl;
    }

    public void setErrorUrl(String errorUrl) {
        this.errorUrl = errorUrl;
    }

    /**
     * Domain on which session cookie should apply, so it doesn't get
     * lost on redirection to the application backdoor.
     *
     * @return session cookie domain
     */
    public String getSessionCookieDomain() {
        return sessionCookieDomain;
    }

    public void setSessionCookieDomain(String sessionCookieDomain) {
        this.sessionCookieDomain = sessionCookieDomain;
    }

    /**
     * Cookie path for session cookie to tighten its application to only certain URL patterns
     *
     * @return path for session cookie
     */
    public String getSessionCookiePath() {
        return sessionCookiePath;
    }

    public void setSessionCookiePath(String sessionCookiePath) {
        this.sessionCookiePath = sessionCookiePath;
    }

    /**
     * Session cookie name. Not all application are Java, so not all sessions use JSESSIONID.
     *
     * @return cookie name
     */
    public String getSessionCookieName() {
        return sessionCookieName;
    }

    public void setSessionCookieName(String sessionCookieName) {
        this.sessionCookieName = sessionCookieName;
    }

    /**
     * Should the cookie be for HTTPS only or whatever traffic.  If set to true
     * the cookie will only appear on HTTPS traffic.
     *
     * @return cooke secure flag
     */
    public boolean getSessionCookieSecureFlag() {
        return sessionCookieSecureFlag;
    }

    public void setSessionCookieSecureFlag(boolean sessionCookieSecureFlag) {
        this.sessionCookieSecureFlag = sessionCookieSecureFlag;
    }

    /**
     * Should the cookie be set with the HttpOnly flag or not
     *
     * @return true if HttpOnly flag should be set false otherwise
     */
    public boolean getSessionCookieHttpOnlyFlag() {
        return sessionCookieHttpOnlyFlag;
    }

    /**
     * Set the HttpOnlyFlag setting
     *
     * @param sessionCookieHttpOnlyFlag true if HttpOnly flag should be set, false otherwise
     */
    public void setSessionCookieHttpOnlyFlag(boolean sessionCookieHttpOnlyFlag) {
        this.sessionCookieHttpOnlyFlag = sessionCookieHttpOnlyFlag;
    }

    /**
     * The cookie domain for the arrowpoint cookie required to traverse the
     * context switch in hosting such that the redirect of a user's browser
     * will actually end up at the right application instance. This cookie is essentially
     * a mapping between the context switch and Apache reverse proxys that sit
     * behind it.
     *
     * @return arrowpoint domain
     */
    public String getArrowPointCookieDomain() {
        return arrowPointCookieDomain;
    }

    public void setArrowPointCookieDomain(String arrowPointCookieDomain) {
        this.arrowPointCookieDomain = arrowPointCookieDomain;
    }

    /**
     * Arrowpoint cookie path
     *
     * @return arrowpoint path
     */
    public String getArrowPointCookiePath() {
        return arrowPointCookiePath;
    }

    public void setArrowPointCookiePath(String arrowPointCookiePath) {
        this.arrowPointCookiePath = arrowPointCookiePath;
    }

    public String getArrowPointCookieName() {
        return arrowPointCookieName;
    }

    public void setArrowPointCookieName(String arrowPointCookieName) {
        this.arrowPointCookieName = arrowPointCookieName;
    }

    /**
     * Arrowpoint cookie value.  It is the middleware configurator's responsibility to
     * setup the correct arrowpoint vlaues so that context switch traversal is successful in hosting.
     *
     * @return arrowpoint value
     */
    public String getArrowPointCookieValue() {
        return arrowPointCookieValue;
    }

    public void setArrowPointCookieValue(String arrowPointCookieValue) {
        this.arrowPointCookieValue = arrowPointCookieValue;
    }

    /**
     * Arrowpoint cookie security flag
     *
     * @return security flag
     */
    public boolean getArrowPointCookieSecureFlag() {
        return arrowPointCookieSecureFlag;
    }

    public void setArrowPointCookieSecureFlag(boolean arrowPointCookieSecureFlag) {
        this.arrowPointCookieSecureFlag = arrowPointCookieSecureFlag;
    }

    /**
     * Should the cookie be set with the HttpOnly flag or not
     *
     * @return true if HttpOnly flag should be set false otherwise
     */
    public boolean getArrowPointCookieHttpOnlyFlag() {
        return arrowPointCookieHttpOnlyFlag;
    }

    public void setArrowPointCookieHttpOnlyFlag(boolean arrowPointCookieHttpOnlyFlag) {
        this.arrowPointCookieHttpOnlyFlag = arrowPointCookieHttpOnlyFlag;
    }

    @Override
    public String toString() {
        return "ConsumerRedirectionConfiguration{" +
                "customerCode='" + customerCode + '\'' +
                ", serviceCode='" + serviceCode + '\'' +
                ", baseUrl='" + baseUrl + '\'' +
                ", serviceUrl='" + serviceUrl + '\'' +
                ", errorUrl='" + errorUrl + '\'' +
                ", sessionCookieDomain='" + sessionCookieDomain + '\'' +
                ", sessionCookiePath='" + sessionCookiePath + '\'' +
                ", sessionCookieName='" + sessionCookieName + '\'' +
                ", sessionCookieSecureFlag=" + sessionCookieSecureFlag +
                ", sessionCookieHttpOnlyFlag=" + sessionCookieHttpOnlyFlag +
                ", arrowPointCookieDomain='" + arrowPointCookieDomain + '\'' +
                ", arrowPointCookiePath='" + arrowPointCookiePath + '\'' +
                ", arrowPointCookieName='" + arrowPointCookieName + '\'' +
                ", arrowPointCookieValue='" + arrowPointCookieValue + '\'' +
                ", arrowPointCookieSecureFlag=" + arrowPointCookieSecureFlag +
                ", arrowPointCookieHttpOnlyFlag=" + arrowPointCookieHttpOnlyFlag +
                '}';
    }
}