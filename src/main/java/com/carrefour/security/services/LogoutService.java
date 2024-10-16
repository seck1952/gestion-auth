package com.carrefour.security.services;

import com.carrefour.security.repository.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
public class LogoutService implements LogoutHandler {

    private final TokenRepository repository;

    public LogoutService(TokenRepository repository) {
        this.repository = repository;
    }

    @Override
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication) {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        jwt = authHeader.substring(7);
        var storeToken = repository.findByToken(jwt).orElse(null);
        if (storeToken != null) {
            storeToken.setExpired(true);
            storeToken.setRevoked(true);
            repository.save(storeToken);
        }

    }
}
