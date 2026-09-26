package com.novaself.authproxy.controller;

import com.novaself.authproxy.model.GoogleTokenResponse;
import com.novaself.authproxy.model.GoogleUserInfo;
import com.novaself.authproxy.model.UserSession;
import com.novaself.authproxy.service.GoogleOAuthService;
import com.novaself.authproxy.service.SessionStore;
import com.novaself.authproxy.service.SessionTokenUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final GoogleOAuthService googleOAuthService;
    private final SessionStore sessionStore;
    private final SessionTokenUtil sessionTokenUtil;
    private final String frontendOrigin;

    public AuthController(GoogleOAuthService googleOAuthService,
                           SessionStore sessionStore,
                           SessionTokenUtil sessionTokenUtil,
                           @Value("${app.frontend-origin}") String frontendOrigin) {
        this.googleOAuthService = googleOAuthService;
        this.sessionStore = sessionStore;
        this.sessionTokenUtil = sessionTokenUtil;
        this.frontendOrigin = frontendOrigin;
    }

    /** Step 1: browser hits this directly (full page navigation), we redirect to Google's consent screen. */
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
     * We exchange the code, store the refresh token server-side, then bounce the
     * browser back to the frontend WITH the session id in the URL (not a cookie) —
     * the frontend grabs it once and stores it itself (localStorage).
     */
    @GetMapping("/callback")
    public ResponseEntity<Void> callback(@RequestParam("code") String code,
                                         @RequestParam("state") String state,
                                         @RequestParam(value = "error", required = false) String error) {
        String errorRedirectBase = frontendOrigin + "/?auth_error=";

        if (error != null) {
            return redirectTo(errorRedirectBase + error + "#/welcome");
        }
        if (!sessionStore.consumeState(state)) {
            return redirectTo(errorRedirectBase + "invalid_state#/welcome");
        }

        try {
            GoogleTokenResponse tokens = googleOAuthService.exchangeCodeForTokens(code);
            if (tokens.hasError() || tokens.getRefreshToken() == null) {
                return redirectTo(errorRedirectBase + "no_refresh_token#/welcome");
            }

            GoogleUserInfo info = googleOAuthService.fetchUserInfo(tokens.getAccessToken());

            UserSession session = new UserSession(
                    info.getSub(), info.getEmail(), info.getName(), info.getPicture(), tokens.getRefreshToken());
            session.cacheAccessToken(tokens.getAccessToken(), tokens.getExpiresIn());

            String sessionId = sessionStore.createSession(session);
            String encodedToken = URLEncoder.encode(sessionId, StandardCharsets.UTF_8);

            // session_token lives in the query string (before the # hash-router part)
            // so window.location.search picks it up regardless of the SPA's route.
            return redirectTo(frontendOrigin + "/?session_token=" + encodedToken + "#/");
        } catch (Exception e) {
            return redirectTo(errorRedirectBase + "exchange_failed#/welcome");
        }
    }

    /**
     * Called by the frontend whenever it needs a fresh access token.
     * Returns a currently-valid access token, transparently refreshing via the
     * stored refresh token when the cached one has expired.
     */
    @GetMapping("/token")
    public ResponseEntity<?> token(HttpServletRequest request) {
        String sessionId = sessionTokenUtil.readSessionId(request);
        UserSession session = sessionStore.get(sessionId);
        if (session == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorBody("not_authenticated"));
        }

        if (!session.hasValidCachedAccessToken()) {
            try {
                GoogleTokenResponse refreshed = googleOAuthService.refreshAccessToken(session.getRefreshToken());
                if (refreshed.hasError()) {
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

    /** Lightweight profile check the frontend can use to decide login vs dashboard. */
    @GetMapping("/me")
    public ResponseEntity<?> me(HttpServletRequest request) {
        String sessionId = sessionTokenUtil.readSessionId(request);
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
        String sessionId = sessionTokenUtil.readSessionId(request);
        UserSession session = sessionStore.get(sessionId);
        if (session != null) {
            googleOAuthService.revokeToken(session.getRefreshToken());
            sessionStore.remove(sessionId);
        }
        // Nothing to clear server-side beyond the session itself — the frontend
        // is responsible for dropping the token from its own localStorage.
        return ResponseEntity.ok().build();
    }

    private ResponseEntity<Void> redirectTo(String url) {
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(url)).build();
    }

    private Map<String, String> errorBody(String code) {
        return Map.of("error", code);
    }
}