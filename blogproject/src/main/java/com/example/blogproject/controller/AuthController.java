package com.example.blogproject.controller;
import com.example.blogproject.dto.RegisterRequest;
import com.example.blogproject.dto.LoginRequest;
import com.example.blogproject.service.AuthService;
import com.example.blogproject.service.AuthenticationResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

        @RestController
        @RequestMapping("/api/auth")
        public class AuthController {

        @Autowired
        private AuthService authService;

        @PostMapping("/signup")
        public ResponseEntity signup(@RequestBody RegisterRequest registerRequest) {
            authService.signup(registerRequest);
            return new ResponseEntity(HttpStatus.OK);
        }

        @PostMapping("/login")
        public AuthenticationResponse login(@RequestBody LoginRequest loginRequest, Authentication authentication) {
            return authService.login(loginRequest, authentication);
        }
    }
