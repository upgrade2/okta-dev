package com.example.demo;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HomeController {

	@RequestMapping("/")
	public String index() {
		System.out.println("directing to home");
		return "home";
	}

	@RequestMapping("/secured/hello")
	public String hello(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
		System.out.println(principal.getName());
		Map<String, String>userAttributes=new HashMap<>();
		userAttributes.put("email", principal.getName());
		model.addAttribute("userAttributes",userAttributes);
		model.addAttribute("emailAddress", principal.getName());
		return "home";
	}
	
	@RequestMapping("/secured")
	public String secured(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
		System.out.println(principal.getName());
		Map<String, String>userAttributes=new HashMap<>();
		userAttributes.put("email", principal.getName());
		model.addAttribute("userAttributes",userAttributes);
		model.addAttribute("emailAddress", principal.getName());
		return "home";
	}

}
