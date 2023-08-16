package com.security.oktaservice.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider.ResponseToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.web.SecurityFilterChain;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfiguration {

//    @Bean
//    public SecurityFilterChain samlSecurityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers("/secured-saml").authenticated()
//                        .anyRequest().authenticated()
//                )
//                .saml2Login(saml2 -> saml2
//                        .authenticationManager(new ProviderManager(samlAuthenticationProvider())))
//                .saml2Logout(withDefaults());
//
//        return http.build();
//    }

    private OpenSaml4AuthenticationProvider samlAuthenticationProvider() {
        OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
        authenticationProvider.setResponseAuthenticationConverter(groupsConverter());
        return authenticationProvider;
    }

    private Converter<ResponseToken, Saml2Authentication> groupsConverter() {
        Converter<ResponseToken, Saml2Authentication> delegate =
                OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter();

        return (responseToken) -> {
            try {
                Saml2Authentication authentication = delegate.convert(responseToken);
                Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
                List<String> groups = principal.getAttribute("groups");
                Set<GrantedAuthority> authorities = new HashSet<>();
                if (groups != null) {
                    groups.stream().map(SimpleGrantedAuthority::new).forEach(authorities::add);
                } else {
                    authorities.addAll(authentication.getAuthorities());
                }
                return new Saml2Authentication(principal, authentication.getSaml2Response(), authorities);
            } catch (Exception e) {
                throw new Saml2Exception("Failed to create Saml2Authentication", e);
            }
        };
    }

    // Uncomment and customize the following code for OAuth 2.0 configuration
//    @Bean
//    public SecurityFilterChain oauthSecurityFilterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepository) throws Exception {
//        http.authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers("/secured-oauth").authenticated()
//                        .anyRequest().authenticated())
//                .oauth2Login(oauth2 -> oauth2
//                        .clientRegistrationRepository(clientRegistrationRepository)
//                        .userInfoEndpoint(userInfo -> userInfo.oidcUserService(oidcUserService(clientRegistrationRepository)))
//                        .loginPage("/login"))
//                .saml2Login(saml2 -> saml2
//                        .authenticationManager(new ProviderManager(samlAuthenticationProvider())))
//                .saml2Logout(withDefaults());
//
//        return http.build();
//    }
//
//    private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService(ClientRegistrationRepository clientRegistrationRepository) {
//        OidcUserService delegate = new OidcUserService();
//        return (userRequest) -> {
//            OidcUser oidcUser = delegate.loadUser(userRequest);
//            return oidcUser;
//        };
//    }
}
