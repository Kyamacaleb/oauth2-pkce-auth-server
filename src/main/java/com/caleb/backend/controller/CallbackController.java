package com.caleb.backend.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class CallbackController {

    @GetMapping("/callback")
    public String callback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String error,
            @RequestParam(required = false) String error_description,
            Model model) {

        if (error != null) {
            model.addAttribute("error", error);
            model.addAttribute("errorDescription", error_description);
            return "callback-error";
        }

        model.addAttribute("code", code);
        return "callback";
    }
}