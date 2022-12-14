package com.example.demo.config;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.example.demo.oauth2.CustomOAuth2User;
import com.example.demo.service.CustomOAuth2UserService;
import com.example.demo.service.UserService;
import com.example.demo.service.impl.UserDetailsServiceImpl;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public UserDetailsService userDetailsService() {
		return new UserDetailsServiceImpl();
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService());
		authProvider.setPasswordEncoder(passwordEncoder());
		return authProvider;
	}

	@Autowired
	private CustomOAuth2UserService oauthUserService;

	@Autowired
	private UserService userService;
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfiguration) throws Exception {
		return authConfiguration.getAuthenticationManager();
	}
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
		http.authorizeRequests().requestMatchers("/", "/login", "/oauth/**").permitAll()
		.anyRequest().authenticated()
		.and().formLogin().permitAll().loginPage("/login")
		.usernameParameter("email")
		.passwordParameter("pass")
		.defaultSuccessUrl("/list")
		.and().oauth2Login().loginPage("/login")
		.userInfoEndpoint().userService(oauthUserService)
		.and().successHandler(new AuthenticationSuccessHandler() {
			
			@Override
			public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
					Authentication authentication) throws IOException, ServletException {
				System.out.println("AuthenticationSuccessHandler invoked");
				System.out.println("Authentication name: " + authentication.getName());
				CustomOAuth2User oauthUser = (CustomOAuth2User) authentication.getPrincipal();
				
				userService.processOAuthPostLogin(oauthUser.getEmail());
				
				response.sendRedirect("/list");
				
			}
		}).and()
		.logout().logoutSuccessUrl("/").permitAll()
		.and()
		.exceptionHandling().accessDeniedPage("/403");
		return http.build();
	}
}
