package com.novaself.authproxy.service;

import com.novaself.authproxy.model.UserSession;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Holds signed-in sessions in memory, keyed by an opaque, unguessable session id
 * (this id IS the cookie value — there's nothing to forge since it's 256 bits
 * of SecureRandom and never derived from user data).
 *
 * NOTE: in-memory means sessions are lost on restart/redeploy. That's an
 * acceptable tradeoff for a single-user personal app on Render's free tier;
 * if this ever needs to survive restarts, swap this for Redis or a DB table
 * without changing any controller code.
 */
@Component
public class SessionStore {

    private final SecureRandom random = new SecureRandom();
    private final ConcurrentMap<String, UserSession> sessions = new ConcurrentHashMap<>();
    // short-lived state values for CSRF-protecting the OAuth redirect (state -> creation time)
    private final ConcurrentMap<String, Long> pendingStates = new ConcurrentHashMap<>();

    private static final long STATE_TTL_MS = 5 * 60 * 1000; // 5 minutes to complete the Google consent flow

    public String createState() {
        String state = randomToken();
        pendingStates.put(state, System.currentTimeMillis());
        return state;
    }

    public boolean consumeState(String state) {
        Long createdAt = pendingStates.remove(state);
        if (createdAt == null) return false;
        return System.currentTimeMillis() - createdAt <= STATE_TTL_MS;
    }

    public String createSession(UserSession session) {
        String sessionId = randomToken();
        sessions.put(sessionId, session);
        return sessionId;
    }

    public UserSession get(String sessionId) {
        if (sessionId == null) return null;
        return sessions.get(sessionId);
    }

    public void remove(String sessionId) {
        if (sessionId != null) sessions.remove(sessionId);
    }

    private String randomToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
