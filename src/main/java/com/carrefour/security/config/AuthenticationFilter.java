package com.carrefour.security.config;

import com.carrefour.security.repository.TokenRepository;
import com.carrefour.security.services.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class AuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final TokenRepository repository;
    private final UserDetailsService userDetailsService;

    public AuthenticationFilter(JwtService jwtService, TokenRepository repository, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.repository = repository;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().contains("/api/v1/auth")) {
            filterChain.doFilter(request,response);
            return;
        }

        final String authHeader = request.getHeader("Authorization");
        final String userEmail;
        final String jwt;
         if (authHeader == null || !authHeader.startsWith("Bearer ")){
             filterChain.doFilter(request, response);
             return;
         }

         jwt = authHeader.substring(7);
         userEmail = jwtService.extractUsername(jwt);
         if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
             UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
             var isTokenValid = repository.findByToken(jwt)
                     .map(token -> !token.isExpired() && token.isRevoked()).orElse(false);
             if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) {
                 UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                         userDetails,
                         null,
                         userDetails.getAuthorities()
                 );
                 authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                 SecurityContextHolder.getContext().setAuthentication(authenticationToken);
             }
         }
         filterChain.doFilter(request, response);

    }
}
