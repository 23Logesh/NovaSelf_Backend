package com.novaself.authproxy.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.novaself.authproxy.model.GoogleTokenResponse;
import com.novaself.authproxy.model.UserSession;
import com.novaself.authproxy.service.CookieUtil;
import com.novaself.authproxy.service.DriveStateService;
import com.novaself.authproxy.service.GoogleAuthExpiredException;
import com.novaself.authproxy.service.GoogleOAuthService;
import com.novaself.authproxy.service.SessionStore;
import com.novaself.authproxy.service.StateMergeService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@RestController
@RequestMapping("/api")
public class StateController {

    private static final Logger log = LoggerFactory.getLogger(StateController.class);

    private final SessionStore sessionStore;
    private final CookieUtil cookieUtil;
    private final GoogleOAuthService googleOAuthService;
    private final DriveStateService driveStateService;
    private final StateMergeService mergeService;
    private final ObjectMapper mapper = new ObjectMapper();

    private final ConcurrentMap<String, Object> userLocks = new ConcurrentHashMap<>();

    public StateController(SessionStore sessionStore,
                            CookieUtil cookieUtil,
                            GoogleOAuthService googleOAuthService,
                            DriveStateService driveStateService,
                            StateMergeService mergeService) {
        this.sessionStore = sessionStore;
        this.cookieUtil = cookieUtil;
        this.googleOAuthService = googleOAuthService;
        this.driveStateService = driveStateService;
        this.mergeService = mergeService;
    }

    @GetMapping("/state")
    public ResponseEntity<?> getState(HttpServletRequest request) {
        String sessionId = cookieUtil.readSessionId(request);
        UserSession session = sessionStore.get(sessionId);
        if (session == null) return unauthorized();

        String accessToken;
        try {
            accessToken = resolveAccessToken(sessionId, session);
        } catch (GoogleAuthExpiredException e) {
            log.warn("[state] GET: access token refresh failed, forcing re-login: {}", e.getMessage());
            return unauthorized();
        } catch (Exception e) {
            log.error("[state] GET: token resolution threw", e);
            return badGateway();
        }

        Object lock = userLocks.computeIfAbsent(session.getGoogleUserId(), k -> new Object());
        synchronized (lock) {
            try {
                DriveStateService.EnsureFileResult ensured = driveStateService.ensureStateFile(accessToken);
                session.setFileId(ensured.fileId());
                JsonNode envelope = mapper.readTree(driveStateService.readState(accessToken, ensured.fileId()));
                return ResponseEntity.ok(responseBody(envelope, ensured.created()));
            } catch (Exception e) {
                log.error("[state] GET: Drive read/ensure failed", e);
                return badGateway();
            }
        }
    }

    @PostMapping("/state")
    public ResponseEntity<?> postState(HttpServletRequest request, @RequestBody Map<String, Object> localData) {
        String sessionId = cookieUtil.readSessionId(request);
        UserSession session = sessionStore.get(sessionId);
        if (session == null) return unauthorized();

        String accessToken;
        try {
            accessToken = resolveAccessToken(sessionId, session);
        } catch (GoogleAuthExpiredException e) {
            log.warn("[state] POST: access token refresh failed, forcing re-login: {}", e.getMessage());
            return unauthorized();
        } catch (Exception e) {
            log.error("[state] POST: token resolution threw", e);
            return badGateway();
        }

        Object lock = userLocks.computeIfAbsent(session.getGoogleUserId(), k -> new Object());
        synchronized (lock) {
            try {
                DriveStateService.EnsureFileResult ensured = driveStateService.ensureStateFile(accessToken);
                session.setFileId(ensured.fileId());

                JsonNode remoteEnvelope = mapper.readTree(driveStateService.readState(accessToken, ensured.fileId()));
                ObjectNode remoteData = remoteEnvelope.path("data").isObject()
                        ? (ObjectNode) remoteEnvelope.get("data") : mapper.createObjectNode();

                ObjectNode localNode = mapper.valueToTree(localData);
                ObjectNode merged = mergeService.merge(localNode, remoteData);

                long now = System.currentTimeMillis();
                ObjectNode newEnvelope = mapper.createObjectNode();
                newEnvelope.put("lastModified", now);
                newEnvelope.set("data", merged);

                driveStateService.writeState(accessToken, ensured.fileId(), mapper.writeValueAsString(newEnvelope));

                return ResponseEntity.ok(responseBody(newEnvelope, ensured.created()));
            } catch (Exception e) {
                log.error("[state] POST: Drive read/merge/write failed", e);
                return badGateway();
            }
        }
    }

    private Map<String, Object> responseBody(JsonNode envelope, boolean isNewlyCreated) {
        Map<String, Object> body = new HashMap<>();
        body.put("data", envelope.path("data"));
        body.put("lastModified", envelope.path("lastModified").asLong(0));
        body.put("isNewlyCreated", isNewlyCreated);
        return body;
    }

    private String resolveAccessToken(String sessionId, UserSession session) throws Exception {
        if (session.hasValidCachedAccessToken()) return session.getCachedAccessToken();
        GoogleTokenResponse refreshed = googleOAuthService.refreshAccessToken(session.getRefreshToken());
        if (refreshed.hasError()) {
            sessionStore.remove(sessionId);
            throw new GoogleAuthExpiredException();
        }
        session.cacheAccessToken(refreshed.getAccessToken(), refreshed.getExpiresIn());
        return session.getCachedAccessToken();
    }

    private ResponseEntity<Map<String, String>> unauthorized() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "not_authenticated"));
    }

    private ResponseEntity<Map<String, String>> badGateway() {
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(Map.of("error", "google_unreachable"));
    }
}