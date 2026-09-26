package com.novaself.authproxy.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieUtil {

    @Value("${app.session-cookie-name}")
    private String cookieName;

    @Value("${app.cookie-secure}")
    private boolean cookieSecure;

    public String readSessionId(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie c : cookies) {
            if (cookieName.equals(c.getName())) return c.getValue();
        }
        return null;
    }

    public ResponseCookie buildSessionCookie(String sessionId, long maxAgeSeconds) {
        return ResponseCookie.from(cookieName, sessionId == null ? "" : sessionId)
                .httpOnly(true)
                .secure(cookieSecure)
                // Frontend (GitHub Pages) and backend (Render) are different origins,
                // so the cookie must be SameSite=None to be sent on the fetch() call.
                .sameSite("None")
                .path("/")
                .maxAge(maxAgeSeconds)
                .build();
    }

    public ResponseCookie clearSessionCookie() {
        return buildSessionCookie(null, 0);
    }
}
