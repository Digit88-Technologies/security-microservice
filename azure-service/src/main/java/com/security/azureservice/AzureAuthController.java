package com.security.azureservice;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;
import java.util.Map;

@Controller
public class AzureAuthController {


    //To Print Attributes for User / Application who logged Into System
        @RequestMapping("/api/login")
    public String welcome(Model model, Principal principal){
        OAuth2AuthenticationToken authentication = (OAuth2AuthenticationToken) principal;
        String name = authentication.getName();
        Map<String, Object> attributes = authentication.getPrincipal().getAttributes();
        model.addAttribute("name", name);
        model.addAttribute("attributes", attributes);
        return "welcome";
    }

    //To Print  User / Application details such as email, etc. who logged Into System
    @RequestMapping("/api/azure/login")
    public String securedOauth(Principal principal, Model model) {
        try {
            System.out.println("Inside OAuth 2.0");
        } catch (Exception e) {
            e.printStackTrace();
            return "error";
        }

        return "secured";
    }
}
