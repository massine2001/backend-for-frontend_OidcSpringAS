package org.massine.bff.api;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.util.Enumeration;

@RestController
public class ApiProxyController {

    private final OAuth2AuthorizedClientManager clientManager;
    private final String apiBaseUrl;

    public ApiProxyController(
            @Qualifier("authorizedClientManager") OAuth2AuthorizedClientManager clientManager,
            @Value("${bff.api-base-url}") String apiBaseUrl
    ) {
        this.clientManager = clientManager;
        this.apiBaseUrl = apiBaseUrl.endsWith("/") ? apiBaseUrl.substring(0, apiBaseUrl.length() - 1) : apiBaseUrl;
    }

    @RequestMapping("/api/**")
    public void proxy(HttpMethod method,
                      HttpServletRequest request,
                      HttpServletResponse response) {
        try {
            String uri = request.getRequestURI();
            String path = uri.substring("/api".length());
            String query = request.getQueryString();
            String target = apiBaseUrl + path + (query != null ? "?" + query : "");

            boolean isPublic =
                    path.startsWith("/public/")
                    || path.equalsIgnoreCase("/api/pool/stats/14");



            String token = null;
            if (!isPublic) {
                token = currentAccessToken();
                if (token == null) {
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    return;
                }
            }

            var url = URI.create(target).toURL();
            var conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestMethod(method.name());
            conn.setDoInput(true);

            Enumeration<String> hdrNames = request.getHeaderNames();
            while (hdrNames.hasMoreElements()) {
                String n = hdrNames.nextElement();
                Enumeration<String> vals = request.getHeaders(n);
                while (vals.hasMoreElements()) {
                    String v = vals.nextElement();
                }
            }

            Enumeration<String> names = request.getHeaderNames();
            while (names.hasMoreElements()) {
                String name = names.nextElement();
                String lower = name.toLowerCase();
                if (lower.equals("host") || lower.equals("cookie") || lower.equals("authorization")
                        || lower.equals("origin") || lower.equals("referer")
                        || lower.equals("content-length") || lower.startsWith("sec-fetch-")) {
                    continue;
                }
                Enumeration<String> vals = request.getHeaders(name);
                while (vals.hasMoreElements()) conn.addRequestProperty(name, vals.nextElement());
            }

            if (!isPublic) conn.setRequestProperty("Authorization", "Bearer " + token);

            if (method == HttpMethod.POST || method == HttpMethod.PUT || method == HttpMethod.PATCH) {
                conn.setDoOutput(true);

                String ct = request.getHeader("Content-Type");
                long len = request.getContentLengthLong();
                if (ct != null) conn.setRequestProperty("Content-Type", ct);

                byte[] payload;
                try (InputStream in = request.getInputStream()) {
                    payload = in.readAllBytes();
                }

                conn.setFixedLengthStreamingMode(payload.length);
                try (OutputStream out = conn.getOutputStream()) {
                    out.write(payload);
                    out.flush();
                }
            }

            int status = conn.getResponseCode();
            response.setStatus(status);
            conn.getHeaderFields().forEach((k, v) -> {
                if (k == null) return;
                for (String val : v) {
                    if (!k.equalsIgnoreCase("Transfer-Encoding")
                            && !k.equalsIgnoreCase("Connection")
                            && !k.equalsIgnoreCase("Set-Cookie")) {
                        response.addHeader(k, val);
                    }
                }
            });

            try (InputStream in = status >= 400 ? conn.getErrorStream() : conn.getInputStream();
                 OutputStream out = response.getOutputStream()) {
                if (in != null) in.transferTo(out);
            }
            conn.disconnect();

        } catch (Exception e) {
            e.printStackTrace();
            try {
                response.setStatus(500);
            } catch (Exception ignored) {}
        }
    }

    private String currentAccessToken() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) return null;
        var req = OAuth2AuthorizeRequest.withClientRegistrationId("spa").principal(auth).build();
        var authorized = clientManager.authorize(req);
        if (authorized != null && authorized.getAccessToken() != null) {
            return authorized.getAccessToken().getTokenValue();
        }
        return null;
    }
}
