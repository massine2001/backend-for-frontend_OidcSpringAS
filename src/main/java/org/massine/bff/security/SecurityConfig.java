package org.massine.bff.security;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(
            HttpSecurity http,
            @Qualifier("corsConfigurationSource") CorsConfigurationSource cors,
            @Value("${bff.external-url}") String spaUrl
    ) throws Exception {

        http
                .cors(c -> c.configurationSource(cors))
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**", "/actuator/**","/logout"))
                .requestCache(rc -> rc.disable())
                .authorizeHttpRequests(reg -> reg

                        .requestMatchers("/", "/index.html", "/favicon.ico", "/assets/**", "/error").permitAll()

                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers("/oauth2/**", "/login/**", "/logout/**").permitAll()
                        .requestMatchers("/api/pool/stats/14").permitAll()
                        .requestMatchers("/api/api/pool/stats/14").permitAll()

                        .requestMatchers("/api/public/**").permitAll()
                        .requestMatchers("/api/public/invitations/**").permitAll()

                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex.authenticationEntryPoint((req, res, authEx) -> {
                    var uri = req.getRequestURI();
                    if (uri.startsWith("/api/")) {
                        res.setStatus(HttpStatus.UNAUTHORIZED.value());
                        res.setContentType("application/json");
                        res.getWriter().write("{\"status\":401,\"error\":\"Unauthorized\"}");
                        return;
                    }
                    String qs = req.getQueryString();
                    String full = req.getRequestURL().toString() + (qs != null ? "?" + qs : "");
                    String returnTo = URLEncoder.encode(full, StandardCharsets.UTF_8);
                    res.sendRedirect("/oauth2/authorization/spa?returnTo=" + returnTo);
                }))
                .oauth2Login(o -> o.successHandler((req, res, auth) -> {
                    String rt = req.getParameter("returnTo");
                    if (rt != null && !rt.isBlank()) res.sendRedirect(rt);
                    else res.sendRedirect(spaUrl);
                }))

                .logout(l -> l.logoutSuccessUrl(spaUrl).invalidateHttpSession(true).deleteCookies("JSESSIONID"));

        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(
            @Value("${bff.external-url}") String spaUrl
    ) {
        var c = new CorsConfiguration();
        c.setAllowedOrigins(List.of(spaUrl));
        c.setAllowedMethods(List.of("GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"));
        c.setAllowedHeaders(List.of("*"));
        c.setAllowCredentials(true);
        var s = new UrlBasedCorsConfigurationSource();
        s.registerCorsConfiguration("/**", c);
        return s;
    }

}
