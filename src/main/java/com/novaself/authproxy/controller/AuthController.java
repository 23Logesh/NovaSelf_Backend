package com.novaself.authproxy.controller;

import com.novaself.authproxy.model.GoogleTokenResponse;
import com.novaself.authproxy.model.GoogleUserInfo;
import com.novaself.authproxy.model.UserSession;
import com.novaself.authproxy.service.CookieUtil;
import com.novaself.authproxy.service.GoogleOAuthService;
import com.novaself.authproxy.service.SessionStore;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final GoogleOAuthService googleOAuthService;
    private final SessionStore sessionStore;
    private final CookieUtil cookieUtil;
    private final String frontendOrigin;

    public AuthController(GoogleOAuthService googleOAuthService,
                           SessionStore sessionStore,
                           CookieUtil cookieUtil,
                           @Value("${app.frontend-origin}") String frontendOrigin) {
        this.googleOAuthService = googleOAuthService;
        this.sessionStore = sessionStore;
        this.cookieUtil = cookieUtil;
        this.frontendOrigin = frontendOrigin;
    }

    /**
     * Step 1: browser hits this directly (full page navigation, e.g. window.location.href = ...),
     * we redirect it to Google's consent screen.
     */
    @GetMapping("/login")
    public ResponseEntity<Void> login() {
        String state = sessionStore.createState();
        String url = googleOAuthService.buildAuthorizationUrl(state);
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(url))
                .build();
    }

    /**
     * Step 2: Google redirects back here with ?code=&state=.
     * We exchange the code, store the refresh token server-side, set the session
     * cookie, then bounce the browser back to the frontend.
     */
    @GetMapping("/callback")
    public ResponseEntity<Void> callback(@RequestParam("code") String code,
                                         @RequestParam("state") String state,
                                         @RequestParam(value = "error", required = false) String error) {
        String redirectBase = frontendOrigin + "/#/login";

        if (error != null) {
            return redirectTo(redirectBase + "?auth_error=" + error);
        }
        if (!sessionStore.consumeState(state)) {
            return redirectTo(redirectBase + "?auth_error=invalid_state");
        }

        try {
            GoogleTokenResponse tokens = googleOAuthService.exchangeCodeForTokens(code);
            if (tokens.hasError() || tokens.getRefreshToken() == null) {
                // No refresh_token usually means the user had already granted consent
                // without access_type=offline previously recorded; prompt=consent above
                // should prevent this, but guard anyway.
                return redirectTo(redirectBase + "?auth_error=no_refresh_token");
            }

            GoogleUserInfo info = googleOAuthService.fetchUserInfo(tokens.getAccessToken());

            UserSession session = new UserSession(
                    info.getSub(), info.getEmail(), info.getName(), info.getPicture(), tokens.getRefreshToken());
            session.cacheAccessToken(tokens.getAccessToken(), tokens.getExpiresIn());

            String sessionId = sessionStore.createSession(session);
            ResponseCookie cookie = cookieUtil.buildSessionCookie(sessionId, 60L * 60 * 24 * 30); // 30 days

            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(frontendOrigin + "/#/"))
                    .header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .build();
        } catch (Exception e) {
            return redirectTo(redirectBase + "?auth_error=exchange_failed");
        }
    }

    /**
     * Called by the frontend on load / whenever it needs a fresh access token.
     * Returns a currently-valid access token, transparently refreshing via the
     * stored refresh token when the cached one has expired. No user gesture needed.
     */
    @GetMapping("/token")
    public ResponseEntity<?> token(HttpServletRequest request) {
        String sessionId = cookieUtil.readSessionId(request);
        UserSession session = sessionStore.get(sessionId);
        if (session == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorBody("not_authenticated"));
        }

        if (!session.hasValidCachedAccessToken()) {
            try {
                GoogleTokenResponse refreshed = googleOAuthService.refreshAccessToken(session.getRefreshToken());
                if (refreshed.hasError()) {
                    // Refresh token itself is dead (revoked/expired) — force a real re-login.
                    sessionStore.remove(sessionId);
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorBody("refresh_failed"));
                }
                session.cacheAccessToken(refreshed.getAccessToken(), refreshed.getExpiresIn());
            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(errorBody("google_unreachable"));
            }
        }

        Map<String, Object> body = new HashMap<>();
        body.put("accessToken", session.getCachedAccessToken());
        body.put("googleUserId", session.getGoogleUserId());
        body.put("email", session.getEmail());
        body.put("name", session.getName());
        body.put("pictureUrl", session.getPictureUrl());
        return ResponseEntity.ok(body);
    }

    /** Lightweight profile check the frontend can use to decide login vs dashboard, without minting a token. */
    @GetMapping("/me")
    public ResponseEntity<?> me(HttpServletRequest request) {
        String sessionId = cookieUtil.readSessionId(request);
        UserSession session = sessionStore.get(sessionId);
        if (session == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorBody("not_authenticated"));
        }
        Map<String, Object> body = new HashMap<>();
        body.put("googleUserId", session.getGoogleUserId());
        body.put("email", session.getEmail());
        body.put("name", session.getName());
        body.put("pictureUrl", session.getPictureUrl());
        return ResponseEntity.ok(body);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        String sessionId = cookieUtil.readSessionId(request);
        UserSession session = sessionStore.get(sessionId);
        if (session != null) {
            googleOAuthService.revokeToken(session.getRefreshToken());
            sessionStore.remove(sessionId);
        }
        ResponseCookie cleared = cookieUtil.clearSessionCookie();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cleared.toString())
                .build();
    }

    private ResponseEntity<Void> redirectTo(String url) {
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(url)).build();
    }

    private Map<String, String> errorBody(String code) {
        return Map.of("error", code);
    }
}
