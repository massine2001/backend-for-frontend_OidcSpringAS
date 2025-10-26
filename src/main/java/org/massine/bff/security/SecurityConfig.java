package org.massine.bff.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, @Value("${bff.external-url}") String spaUrl) throws Exception {
        var success = new SavedRequestAwareAuthenticationSuccessHandler();
        success.setDefaultTargetUrl(spaUrl);
        success.setAlwaysUseDefaultTargetUrl(true);
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(reg -> reg
                        .requestMatchers("/", "/index.html", "/favicon.ico", "/assets/**").permitAll()
                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers("/oauth2/**", "/login/**", "/logout/**").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(o -> o.defaultSuccessUrl(spaUrl, true) )
                .logout(l -> l.logoutUrl("/logout").logoutSuccessUrl(spaUrl).invalidateHttpSession(true).deleteCookies("JSESSIONID"))
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**","/actuator/**"));

        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:5174"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

}
