package org.massine.bff.api;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@RestController
@RequestMapping("/api/public")
public class PublicAuthController {

    private final String authBaseUrl;
    private final String bffUrl;
    private final String spaUrl;

    private final RestTemplate rest = new RestTemplate();

    public PublicAuthController(
            @Value("${auth.base-url}") String authBaseUrl,
            @Value("${bff.internal-url}") String bffUrl,
            @Value("${bff.external-url}") String spaUrl
    ) {
        this.authBaseUrl = authBaseUrl;
        this.bffUrl = bffUrl;
        this.spaUrl = spaUrl;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> body) {
        try {
            String email = body.get("email");
            String password = body.get("password");

            if (email == null || password == null) {
                return ResponseEntity.badRequest().body(Map.of("success", false, "message", "Email et mot de passe requis"));
            }

            String loginUrl = bffUrl + "/oauth2/authorization/spa?returnTo="
                    + URLEncoder.encode(spaUrl, StandardCharsets.UTF_8);

            String registerUrl = authBaseUrl + "/register";

            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("email", email);
            form.add("password", password);
            form.add("loginUrl", loginUrl);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            HttpEntity<MultiValueMap<String, String>> req = new HttpEntity<>(form, headers);

            ResponseEntity<String> resp = rest.postForEntity(registerUrl, req, String.class);

            if (resp.getStatusCode().is2xxSuccessful()) {
                return ResponseEntity.ok(Map.of("success", true, "message", "Vérifiez votre e-mail pour confirmer votre compte"));
            } else {
                return ResponseEntity.status(resp.getStatusCode()).body(Map.of("success", false, "message", "Erreur côté serveur d’authentification"));
            }
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("success", false, "message", "Erreur interne BFF"));
        }
    }
}

