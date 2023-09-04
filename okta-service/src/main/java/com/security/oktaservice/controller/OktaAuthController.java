package com.security.oktaservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.reactive.function.client.WebClient;

import java.security.Principal;

@Controller
public class OktaAuthController {

    @Autowired
    private WebClient.Builder webClientBuilder;;

    @RequestMapping("/secured-saml")
    public String securedSaml(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
        model.addAttribute("name", principal.getName());
        model.addAttribute("emailAddress", principal.getFirstAttribute("email"));
        model.addAttribute("userAttributes", principal.getAttributes());
        return "home";
    }

//    @RequestMapping("/redirect/azure/login")
//    public String nonSecured() {
//
//        return webClientBuilder.build().get().
//                uri("http://azure-service/api/azure/login").
//                retrieve().
//                bodyToMono(String.class).
//                block();
//    }

    @RequestMapping("/api/okta/login")
    public String securedOauth(Principal principal, Model model) {
        try {
//            model.addAttribute("name", principal.getName());

//            String email = principal instanceof Saml2AuthenticatedPrincipal ?
//                    ((Saml2AuthenticatedPrincipal) principal).getFirstAttribute("email") :
//                    null;
//            model.addAttribute("emailAddress", email);
//
//            String principalName = principal.getName();

        } catch (Exception e) {
            e.printStackTrace();
            return "error";
        }

        return "secured";
    }


}
