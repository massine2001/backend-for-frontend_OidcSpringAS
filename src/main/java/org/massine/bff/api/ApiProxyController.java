package org.massine.bff.api;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.net.URI;
import java.util.Enumeration;


@RestController
public class ApiProxyController {

    private final WebClient webClient;
    private final String apiBaseUrl;
    private final OAuth2AuthorizedClientManager clientManager;

    public ApiProxyController(
            WebClient webClient,
            @Value("${bff.api-base-url}") String apiBaseUrl,
            @Qualifier("authorizedClientManager") OAuth2AuthorizedClientManager clientManager
    ) {
        this.webClient = webClient;
        this.apiBaseUrl = apiBaseUrl.endsWith("/") ? apiBaseUrl.substring(0, apiBaseUrl.length() - 1) : apiBaseUrl;
        this.clientManager = clientManager;
    }

    @RequestMapping("/api/**")
    public ResponseEntity<byte[]> proxy(
            HttpMethod method,
            HttpServletRequest request,
            @RequestBody(required = false) byte[] body
    ) throws IOException {

        String token = currentAccessToken();
        if (token == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String requestUri = request.getRequestURI();
        String path = requestUri.substring("/api".length());
        String query = request.getQueryString();
        String target = apiBaseUrl + path + (query != null ? "?" + query : "");

        WebClient.RequestBodySpec spec = webClient.method(method).uri(URI.create(target));

        HttpHeaders headers = extractForwardHeaders(request);
        headers.setBearerAuth(token);
        System.out.println("BFF DEBUG: Bearer injecté (" + token.length() + " chars)");

        WebClient.RequestHeadersSpec<?> headersSpec;
        if (method == HttpMethod.POST || method == HttpMethod.PUT || method == HttpMethod.PATCH || method == HttpMethod.DELETE) {
            byte[] payload = (body != null) ? body : readRequestBodyIfAny(request);
            headersSpec = spec.headers(h -> h.addAll(headers))
                    .body(BodyInserters.fromValue(payload != null ? payload : new byte[0]));
        } else {
            headersSpec = spec.headers(h -> h.addAll(headers));
        }
        ProxyResult result = headersSpec.exchangeToMono(resp ->
                resp.bodyToMono(byte[].class)
                        .defaultIfEmpty(new byte[0])
                        .map(b -> {
                            HttpHeaders out = filterResponseHeaders(resp.headers().asHttpHeaders());
                            return new ProxyResult(resp.statusCode(), out, b);
                        })
        ).block();

        if (result == null) return ResponseEntity.status(HttpStatus.BAD_GATEWAY).build();

        return ResponseEntity.status(result.status()).headers(result.headers()).body(result.body());
    }

    private static record ProxyResult(org.springframework.http.HttpStatusCode status, HttpHeaders headers, byte[] body) {}

    private String currentAccessToken() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) return null;
        var req = OAuth2AuthorizeRequest
                .withClientRegistrationId("spa")
                .principal(auth)
                .build();
        var authorized = clientManager.authorize(req);
        return (authorized != null && authorized.getAccessToken() != null)
                ? authorized.getAccessToken().getTokenValue()
                : null;
    }

    private HttpHeaders extractForwardHeaders(HttpServletRequest req) {
        HttpHeaders h = new HttpHeaders();
        Enumeration<String> names = req.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            String lower = name.toLowerCase();

            if (lower.equals("host")
                    || lower.equals("cookie")
                    || lower.equals("authorization")
                    || lower.equals("origin")
                    || lower.equals("referer")
                    || lower.equals("content-length")
                    || lower.startsWith("sec-fetch-")) {
                continue;
            }

            Enumeration<String> values = req.getHeaders(name);
            while (values.hasMoreElements()) {
                h.add(name, values.nextElement());
            }
        }
        return h;
    }

    private HttpHeaders filterResponseHeaders(HttpHeaders in) {
        HttpHeaders out = new HttpHeaders();
        in.forEach((k, vals) -> {
            String lower = k.toLowerCase();
            if (lower.equals("transfer-encoding") || lower.equals("set-cookie") || lower.equals("connection")) return;
            out.put(k, vals);
        });
        return out;
    }

    private byte[] readRequestBodyIfAny(HttpServletRequest request) throws IOException {
        try { return StreamUtils.copyToByteArray(request.getInputStream()); }
        catch (Exception e) { return null; }
    }
}
