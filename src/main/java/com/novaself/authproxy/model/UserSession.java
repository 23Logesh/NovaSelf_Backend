package com.novaself.authproxy.model;

/**
 * One signed-in NovaSelf user, keyed off an opaque session id (the cookie value).
 * Holds the long-lived Google refresh token plus a short-lived cached access
 * token so we don't hit Google's token endpoint on every request.
 */
public class UserSession {

    private final String googleUserId;
    private final String email;
    private final String name;
    private final String pictureUrl;
    private final String refreshToken;

    private volatile String cachedAccessToken;
    private volatile long accessTokenExpiresAtEpochMs;

    public UserSession(String googleUserId, String email, String name, String pictureUrl, String refreshToken) {
        this.googleUserId = googleUserId;
        this.email = email;
        this.name = name;
        this.pictureUrl = pictureUrl;
        this.refreshToken = refreshToken;
    }

    public String getGoogleUserId() { return googleUserId; }
    public String getEmail() { return email; }
    public String getName() { return name; }
    public String getPictureUrl() { return pictureUrl; }
    public String getRefreshToken() { return refreshToken; }

    public String getCachedAccessToken() { return cachedAccessToken; }

    public boolean hasValidCachedAccessToken() {
        return cachedAccessToken != null && System.currentTimeMillis() < accessTokenExpiresAtEpochMs;
    }

    public void cacheAccessToken(String accessToken, long expiresInSeconds) {
        this.cachedAccessToken = accessToken;
        // Refresh 60s early so we never hand out a token that expires mid-request.
        this.accessTokenExpiresAtEpochMs = System.currentTimeMillis() + Math.max(0, (expiresInSeconds - 60)) * 1000L;
    }
}
