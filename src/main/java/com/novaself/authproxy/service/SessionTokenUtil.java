package com.novaself.authproxy.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

/**
 * Replaces CookieUtil. The session id is no longer a browser cookie — cross-site
 * cookies between the Vercel frontend and Render backend were being dropped/blocked
 * (confirmed via DevTools: the cookie never reached the onrender.com domain).
 *
 * Instead the frontend stores the session id itself (localStorage) and sends it
 * explicitly as "Authorization: Bearer <sessionId>" on every request. This is not
 * a cookie, so no browser cross-site cookie policy applies to it at all.
 */
@Component
public class SessionTokenUtil {

    private static final String PREFIX = "Bearer ";

    public String readSessionId(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith(PREFIX)) return null;
        String token = header.substring(PREFIX.length()).trim();
        return token.isEmpty() ? null : token;
    }
}