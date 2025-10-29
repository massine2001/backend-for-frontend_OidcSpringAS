package org.massine.bff.oauth;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;

@Configuration
public class WebClientConfig {

        @Bean
        @Qualifier("authorizedClientManager")
        OAuth2AuthorizedClientManager authorizedClientManager(
                ClientRegistrationRepository repo,
                OAuth2AuthorizedClientRepository clients
        ) {
            var provider = OAuth2AuthorizedClientProviderBuilder.builder()
                    .authorizationCode()
                    .refreshToken()
                    .build();
            var manager = new DefaultOAuth2AuthorizedClientManager(repo, clients);
            manager.setAuthorizedClientProvider(provider);
            return manager;
        }

        @Bean
        @Qualifier("oauth2WebClient")
        WebClient oauth2WebClient(@Qualifier("authorizedClientManager") OAuth2AuthorizedClientManager manager) {
            var oauth2 = new ServletOAuth2AuthorizedClientExchangeFilterFunction(manager);
            oauth2.setDefaultClientRegistrationId("spa");
            oauth2.setDefaultOAuth2AuthorizedClient(true);
            return WebClient.builder().filter(oauth2).build();
        }

        @Bean
        @Qualifier("plainWebClient")
        WebClient plainWebClient() {
            return WebClient.builder().build();
        }
    }



