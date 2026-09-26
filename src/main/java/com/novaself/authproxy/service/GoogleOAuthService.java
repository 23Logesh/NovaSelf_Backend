package com.novaself.authproxy.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.novaself.authproxy.model.GoogleTokenResponse;
import com.novaself.authproxy.model.GoogleUserInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

@Service
public class GoogleOAuthService {

    private static final String AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
    private static final String TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
    private static final String USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v3/userinfo";
    private static final String REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke";

    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;
    private final String scopes;

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    private final ObjectMapper mapper = new ObjectMapper();

    public GoogleOAuthService(
            @Value("${google.client-id}") String clientId,
            @Value("${google.client-secret}") String clientSecret,
            @Value("${google.redirect-uri}") String redirectUri,
            @Value("${google.scopes}") String scopes) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
        this.scopes = scopes;
    }

    /** Builds the Google consent-screen URL the browser should be redirected to. */
    public String buildAuthorizationUrl(String state) {
        String encodedScopes = URLEncoder.encode(scopes.trim().replaceAll("\\s+", " "), StandardCharsets.UTF_8);
        return AUTH_ENDPOINT
                + "?client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&response_type=code"
                + "&scope=" + encodedScopes
                // offline + consent guarantees a refresh_token comes back even on repeat logins
                + "&access_type=offline"
                + "&prompt=consent"
                + "&include_granted_scopes=true"
                + "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);
    }

    /** Exchanges the one-time authorization code for an access + refresh token pair. */
    public GoogleTokenResponse exchangeCodeForTokens(String code) throws Exception {
        String form = "code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8)
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&grant_type=authorization_code";
        return postForm(form);
    }

    /** Uses a stored refresh token to mint a fresh short-lived access token. */
    public GoogleTokenResponse refreshAccessToken(String refreshToken) throws Exception {
        String form = "refresh_token=" + URLEncoder.encode(refreshToken, StandardCharsets.UTF_8)
                + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8)
                + "&grant_type=refresh_token";
        return postForm(form);
    }

    private GoogleTokenResponse postForm(String form) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(TOKEN_ENDPOINT))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        return mapper.readValue(response.body(), GoogleTokenResponse.class);
    }

    public GoogleUserInfo fetchUserInfo(String accessToken) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(USERINFO_ENDPOINT))
                .header("Authorization", "Bearer " + accessToken)
                .GET()
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Failed to fetch Google userinfo: HTTP " + response.statusCode() + " " + response.body());
        }
        return mapper.readValue(response.body(), GoogleUserInfo.class);
    }

    /** Best-effort revoke on logout. Failures are ignored — the session is dropped locally regardless. */
    public void revokeToken(String token) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(REVOKE_ENDPOINT))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString("token=" + URLEncoder.encode(token, StandardCharsets.UTF_8)))
                    .build();
            http.send(request, HttpResponse.BodyHandlers.discarding());
        } catch (Exception ignored) {
            // Revocation is best-effort; local session removal already happened.
        }
    }
}
