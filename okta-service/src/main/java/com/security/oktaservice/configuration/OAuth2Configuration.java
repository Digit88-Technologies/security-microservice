package com.security.oktaservice.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;


@Configuration
public class OAuth2Configuration {

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("okta")
                .clientId("0oaaqutdyvaLPKDkq5d7")
                .clientSecret("Xyq8ISLzXF-w9HPLWicPLma4j8BL_P-ObiK74L16oCh1OiL9dllS-fOvRs1Kah3U")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // Use the enum directly
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://www.youtube.com/")
                .scope("openid", "profile", "email")
                .authorizationUri("https://dev-02015639.okta.com/oauth2/v1/authorize")
                .tokenUri("https://dev-02015639.okta.com/oauth2/v1/token")
                .userInfoUri("https://dev-02015639.okta.com/oauth2/v1/userinfo")
                .userNameAttributeName("sub")
                .jwkSetUri("https://dev-02015639.okta.com/oauth2/v1/keys")
                .clientName("Okta")
                .build();

        return new InMemoryClientRegistrationRepository(clientRegistration);
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(ClientRegistrationRepository clientRegistrationRepository) {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
    }
}
