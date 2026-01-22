package com.business.busi.controller;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.business.busi.configuration.JwtService;
import com.business.busi.entity.Customer;
import com.business.busi.service.CustomerService;




@RestController
@RequestMapping("/bussiness")
public class CustomerController {
	
	@Autowired
	private CustomerService service;
	
	@Autowired
	private AuthenticationManager authManager;
	
	@Autowired
	private JwtService jwt;

	@GetMapping("/check")
	public String details() {
		return "welcome";
	}
	
	@PostMapping("/register")
	public ResponseEntity<String> registerWithCustomer(@RequestBody Customer customer) {
	boolean	 status = service.registerWithCustomer(customer);
		if(status) {
			return new ResponseEntity<>("sucess",HttpStatus.OK);
		}else {
			return new ResponseEntity<>("failed",HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}
	
//	@PostMapping("/login")
//	public ResponseEntity<String> login(@RequestBody Customer customer){
//		
//		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(customer.getEmail(), customer.getPassword());
//	    Authentication authenticate	= authManager.authenticate(token);
//	    boolean status = authenticate.isAuthenticated();
//	    
//	    if(status) {
//	    	return new ResponseEntity<>("welcome",HttpStatus.OK);
//	    }else {
//	    	return new ResponseEntity<>("failed",HttpStatus.BAD_REQUEST);
//	    }
//	    
//	}
	
	@PostMapping("/login")
	public ResponseEntity<Map<String,String>> login(@RequestBody Customer customer) throws NoSuchAlgorithmException{
		
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(customer.getName(), customer.getPassword());
	    Authentication authenticate	= authManager.authenticate(token);
	    Map<String,String> storeToken = new HashMap<String,String>();
	    if(authenticate.isAuthenticated()) {
	    	String jwtToken = jwt.generateToken(customer.getName()) ;
	    	storeToken.put("token", jwtToken);
	    	return new ResponseEntity<Map<String,String>>(storeToken,HttpStatus.OK);
	    }
	    storeToken.put("token", "invalid credentials");
	    return new ResponseEntity<Map<String,String>>(storeToken,HttpStatus.BAD_REQUEST);
	    
	}
	
	 @PostMapping("/logout")
	    public Map<String, String> logout(@RequestHeader("Authorization") String authHeader) throws NoSuchAlgorithmException{
		 if (authHeader != null && authHeader.startsWith("Bearer ")) {
	        String token = authHeader.substring(7);
	        jwt.deleteToken(token);
		 }
	        Map<String, String> response = new HashMap<>();
	        response.put("message", "Logged out successfully");
	        return response;
	    }

	    @GetMapping("/validate")
	    public Map<String, Object> validateToken(@RequestHeader("Authorization") String authHeader) throws NoSuchAlgorithmException{
	    	boolean valid = false;
	    	if (authHeader != null && authHeader.startsWith("Bearer ")) {
	        String token = authHeader.substring(7);
	        valid =  jwt.isTokenValid(token);
	    	}
	        Map<String, Object> response = new HashMap<>();
	        response.put("valid", valid);
	        return response;
	    	
	    }
	
	
}
