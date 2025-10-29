# backend-for-frontend_OidcSpringAS

Description
- Backend\-for\-Frontend (BFF) Spring Boot utilisant OIDC pour l'authentification.
- Structure principale dans `src/main/java/org/massine/bff` (contrôleurs, config OAuth, sécurité).

Prérequis
- Java 17+ installé.
- Maven (ou utilisez les wrappers `mvnw.cmd` / `mvnw`).
- Docker (optionnel).

Installation & exécution (Windows)
1. Compiler :
   - `mvnw.cmd clean package`
2. Lancer depuis Maven :
   - `mvnw.cmd spring-boot:run`
3. Lancer le jar :
   - `java -jar target/backend-for-frontend_OidcSpringAS-0.0.1-SNAPSHOT.jar`
4. Ajouter un .env exemple
    BFF_EXTERNAL_URL=http://localhost:5174
    AS_ISSUER_URI=https://auth.massine.org
    OAUTH_CLIENT_ID=bff
    OAUTH_CLIENT_SECRET=bff
    OAUTH_SCOPES=openid,profile,email,api.read,offline_access
    API_BASE_URL=http://localhost:8080
    SERVER_PORT=5173
    BFF_INTERNAL_URL=http://localhost:5173


Configuration
- Fichier principal : `src/main/resources/application.properties`
- Configurez les propriétés OIDC / client OAuth2 dans `application.properties` (client id/secret, issuer uri, scopes, redirect URIs).
- Exemples de clés à définir : `spring.security.oauth2.client.registration.*`, `spring.security.oauth2.client.provider.*`.

Points d'entrée
- Contrôleurs principaux :
  - `ApiProxyController` : proxie les appels API backend.
  - `PublicAuthController` : endpoints d'authentification publique.
- Configuration :
  - `WebClientConfig` : configuration des WebClient pour appels externes.
  - `SecurityConfig` : règles de sécurité et protection des endpoints.
