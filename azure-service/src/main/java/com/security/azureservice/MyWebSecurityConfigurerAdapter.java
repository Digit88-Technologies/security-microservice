package com.security.azureservice;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
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
public class MyWebSecurityConfigurerAdapter {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // all endpoints require authentication
        http.authorizeRequests()
//                .requestMatchers("/api/azure/**").permitAll();
                .requestMatchers("/api/azure/**").authenticated();
//                .anyRequest().authenticated();

        // configure a custom authentication manager resolver
        http.oauth2ResourceServer((oauth2ResourceServer) ->
                oauth2ResourceServer.authenticationManagerResolver(resolver()));

        return http.build();
    }
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//
//        // all endpoints require authentication
//        http.authorizeRequests().anyRequest().authenticated();
//
//        // configure a custom authentication manager resolver
////        http.oauth2ResourceServer().authenticationManagerResolver(customAuthenticationManager());
//        http.oauth2ResourceServer().authenticationManagerResolver(customAuthenticationManagerResolver());
//
//    }


    //Multiple Auth Managers are configured here in below method



//        AuthenticationManagerResolver<HttpServletRequest> customAuthenticationManagerResolver() {
//
//            LinkedHashMap<RequestMatcher, AuthenticationManager> authenticationManagers = new LinkedHashMap<>();
//
//            System.out.println("Inside Custom Resolver");
//
//
//        // Adding multiple authentication managers for different use cases
//
////        RequestMatcher azureMatcher = new AntPathRequestMatcher("/azure/**");
//
//        List<String> readMethod = Arrays.asList("HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE");
//        RequestMatcher readMethodRequestMatcher = request -> readMethod.contains(request.getMethod());
//        RequestMatcher azureMatcher = new RequestHeaderRequestMatcher("ProviderType", "azure");
//        RequestMatcher finalAzureMatcher = new AndRequestMatcher(
//                azureMatcher,
//                readMethodRequestMatcher
//        );
//
//        authenticationManagers.put(finalAzureMatcher, azureJwt());
//
////        RequestMatcher oktaMatcher = new AntPathRequestMatcher("/okta/**");
//        RequestMatcher oktaMatcher = new RequestHeaderRequestMatcher("ProviderType", "okta");
//        RequestMatcher finalOktaMatcher = new AndRequestMatcher(
//                oktaMatcher,
//                readMethodRequestMatcher
//        );
//        authenticationManagers.put(finalOktaMatcher, oktaJwt()); // You can adjust this to use the correct AuthenticationManager
//
//            return new
//        }

        //new test resolver
        AuthenticationManagerResolver<HttpServletRequest> resolver() {

            return request -> {
                if (request.getHeader("ProviderType").matches("okta")) {

                    return oktaJwt();
                }
                System.out.println("Inside Custom Resolver");

                return azureJwt();
            };
        }

        //end test resolver


//    private AuthenticationManagerResolver<HttpServletRequest> azureAuthenticationManager() {
//        LinkedHashMap<RequestMatcher, AuthenticationManager> authenticationManagers = new LinkedHashMap<>();
//
//        // USE JWT tokens (locally validated) to validate HEAD, GET, and OPTIONS requests
//        List<String> readMethod = Arrays.asList("HEAD", "GET", "OPTIONS");
//        RequestMatcher readMethodRequestMatcher = request -> readMethod.contains(request.getMethod());
//        authenticationManagers.put(readMethodRequestMatcher, azureJwt());
//
//        // all other requests will use opaque tokens (remotely validated)
//        return new RequestMatchingAuthenticationManagerResolver(authenticationManagers);    }
//
//
//    AuthenticationManagerResolver<HttpServletRequest> customAuthenticationManager() {
//        LinkedHashMap<RequestMatcher, AuthenticationManager> authenticationManagers = new LinkedHashMap<>();
//
//        // USE JWT tokens (locally validated) to validate HEAD, GET, and OPTIONS requests
//        List<String> readMethod = Arrays.asList("HEAD", "GET", "OPTIONS");
//        RequestMatcher readMethodRequestMatcher = request -> readMethod.contains(request.getMethod());
//        authenticationManagers.put(readMethodRequestMatcher, jwt());
//
//        // all other requests will use opaque tokens (remotely validated)
//        return new RequestMatchingAuthenticationManagerResolver(authenticationManagers);
//    }

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
}