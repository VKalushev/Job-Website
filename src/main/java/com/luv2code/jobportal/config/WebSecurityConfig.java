package com.luv2code.jobportal.config;

import com.luv2code.jobportal.services.CustomUserDetailService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class WebSecurityConfig {

    private final CustomUserDetailService customUserDetailService;
    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;


    private final String[] publicUrl = {"/",
            "/global-search/**",
            "/register",
            "/register/**",
            "/webjars/**",
            "/resources/**",
            "/assets/**",
            "/css/**",
            "/summernote/**",
            "/js/**",
            "/*.css",
            "/*.js",
            "/*.js.map",
            "/fonts**", "/favicon.ico", "/resources/**", "/error"};

    public WebSecurityConfig(CustomUserDetailService customUserDetailService, CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler) {
        this.customAuthenticationSuccessHandler = customAuthenticationSuccessHandler;
        this.customUserDetailService = customUserDetailService;
    }

    @Bean
    protected SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authenticationProvider(authenticationProvider());

        httpSecurity.authorizeHttpRequests(auth -> {
            auth.requestMatchers(publicUrl).permitAll();
            auth.anyRequest().authenticated();
        });

        httpSecurity.formLogin(form -> form.loginPage("/login").permitAll().successHandler(customAuthenticationSuccessHandler))
                .logout(logout -> {
                    logout.logoutUrl("/logout");
                    logout.logoutSuccessUrl("/");
                }).cors(Customizer.withDefaults()).csrf(AbstractHttpConfigurer::disable);

        return httpSecurity.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        authenticationProvider.setUserDetailsService(customUserDetailService);
        return authenticationProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
