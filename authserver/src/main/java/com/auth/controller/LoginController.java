package com.auth.controller;

import com.auth.dto.UserObjDto;
import com.auth.service.AuthServiceImpl;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Controller
public class LoginController {

    @Autowired
    AuthServiceImpl authService;

    @GetMapping("/login")
    public String loginPage(Model model, HttpSession session, @RequestParam(required = false) String error) {
        if (error != null) {
            String errorMsg = (String) session.getAttribute("errorMessage");
            model.addAttribute("loginError", errorMsg);
            session.removeAttribute("errorMessage");
        }
        return "login"; // same template
    }

    @GetMapping("/home")
    public String homePage() {
        return "home"; // Spring looks for templates/login_backup.html
    }

    @GetMapping("/signup")
    public String signup(Model model) {
        model.addAttribute("user", new UserObjDto());
        model.addAttribute("roles", List.of("USER", "DRIVER", "RIDER"));
        return "signup";
    }
    @PostMapping("/signup")
    public String processSignup(@Valid @ModelAttribute("user") UserObjDto userDto,
                                BindingResult result,
                                RedirectAttributes redirectAttributes,
                                Model model,
                                @RequestParam(value = "roles", required = false) List<String> roles) {

        if (roles == null || roles.isEmpty()) {
            // Add error message and re-render signup page
            model.addAttribute("roles", List.of("USER", "DRIVER", "RIDER"));
            model.addAttribute("errorMessage", "Please select at least one role.");
            return "signup";
        }
        if (result.hasErrors()) {

            return "signup";
        }
        System.out.println("Selected roles: " + roles);
        authService.createUser(userDto,roles);
        redirectAttributes.addAttribute("signupSuccess", true);
        return "redirect:/login";
    }
}


