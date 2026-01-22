package com.business.busi.configuration;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.business.busi.service.CustomerService;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class AppFilter extends OncePerRequestFilter {
	
	private static final Logger logger = LoggerFactory.getLogger(AppFilter.class); 
	
	 @Autowired
	 private JwtService jwtService;
	
	@Autowired
	private CustomerService service;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		String token = null;
		String userName = null;

       
		String header = request.getHeader("Authorization");
		try {
		if(header != null && header.startsWith("Bearer ")) {
			token = header.substring(7);
			userName = jwtService.extractUsername(token);
		}
		
		if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = service.loadUserByUsername(userName);
   
        boolean isValidate = jwtService.validateToken(token,userDetails);
           if(isValidate){
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
           
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
           }
        }
		 }catch (JwtException  e) {
			 logger.error("JwtException doFilterInternal failed: {}",  e);
	     }catch (Exception  e) {
			 logger.error("Exception doFilterInternal failed: {}",  e);
	     }
		
		filterChain.doFilter(request, response);
		
	}

}
