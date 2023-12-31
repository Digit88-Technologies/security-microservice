package com.security.oktaservice.configuration;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtBearerTokenAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.*;


@Configuration
public class OAuth2Configuration {



    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // all endpoints require authentication
        http.authorizeRequests()
                .requestMatchers("/api/okta/**").permitAll();
//                .requestMatchers("/api/okta/**").authenticated();
//                .anyRequest().authenticated();

        // configure a custom authentication manager resolver
        http.oauth2ResourceServer((oauth2ResourceServer) ->
                oauth2ResourceServer.authenticationManagerResolver(resolver()));

        return http.build();
    }

    AuthenticationManagerResolver<HttpServletRequest> resolver() {

        return request -> {
            if (request.getHeader("ProviderType").matches("okta")) {
                System.out.println("Inside Okta Custom Resolver");

                return oktaJwt();
            }
            System.out.println("Inside Azure Custom Resolver");

            return azureJwt();
        };
    }

    AuthenticationManager azureJwt() {
        // this is the keys endpoint for okta
//        String issuer = "https://login.microsoftonline.com/32fff58c-05d9-4790-8c68-011881d8175a";

        String issuer = "https://sts.windows.net/32fff58c-05d9-4790-8c68-011881d8175a/";
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri("https://login.microsoftonline.com/32fff58c-05d9-4790-8c68-011881d8175a/discovery/v2.0/keys").jwsAlgorithm(SignatureAlgorithm.RS256).build();
//        issuer = oAuth2ClientProperties.getProvider().get("azure").getIssuerUri();
//        jwtDecoder = NimbusJwtDecoder.withJwkSetUri("https://login.microsoftonline.com/e4865784-7e1d-4a19-be59-0103c98ea13d/discovery/v2.0/keys").build();


        // okta recommends validating the `iss` and `aud` claims
        // see: https://developer.okta.com/docs/guides/validate-access-tokens/java/overview/
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtTimestampValidator());
        validators.add(new JwtIssuerValidator(issuer));
        validators.add(token -> {
            Set<String> expectedAudience = new HashSet<>();
            expectedAudience.add("api://076c4363-7f4a-4205-8eaa-8d45e429fb3b"); // this is the default value, update this accordingly
            return !Collections.disjoint(token.getAudience(), expectedAudience)
                    ? OAuth2TokenValidatorResult.success()
                    : OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                    "This aud claim is not equal to the configured audience",
                    "https://tools.ietf.org/html/rfc6750#section-3.1"));
        });
        OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(validators);
        jwtDecoder.setJwtValidator(validator);

        JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(jwtDecoder);
        authenticationProvider.setJwtAuthenticationConverter(new JwtBearerTokenAuthenticationConverter());
        return authenticationProvider::authenticate;
    }

    AuthenticationManager oktaJwt() {
        // this is the keys endpoint for okta
        String issuer = "https://dev-02015639.okta.com/oauth2/default";
        NimbusJwtDecoder jwtDecoder = null;
        String jwkSetUri = issuer + "/v1/keys";

        jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();


        // okta recommends validating the `iss` and `aud` claims
        // see: https://developer.okta.com/docs/guides/validate-access-tokens/java/overview/
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtTimestampValidator());
        validators.add(new JwtIssuerValidator(issuer));
        validators.add(token -> {
            Set<String> expectedAudience = new HashSet<>();
            expectedAudience.add("api://default"); // this is the default value, update this accordingly
            return !Collections.disjoint(token.getAudience(), expectedAudience)
                    ? OAuth2TokenValidatorResult.success()
                    : OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                    "This aud claim is not equal to the configured audience",
                    "https://tools.ietf.org/html/rfc6750#section-3.1"));
        });
        OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(validators);
        jwtDecoder.setJwtValidator(validator);

        JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(jwtDecoder);
        authenticationProvider.setJwtAuthenticationConverter(new JwtBearerTokenAuthenticationConverter());
        return authenticationProvider::authenticate;
    }
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("okta")
                .clientId("0oaaqutdyvaLPKDkq5d7")
                .clientSecret("Xyq8ISLzXF-w9HPLWicPLma4j8BL_P-ObiK74L16oCh1OiL9dllS-fOvRs1Kah3U")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // Use the enum directly
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8080/login/oauth2/code/okta")
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
