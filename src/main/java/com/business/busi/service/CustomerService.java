package com.business.busi.service;
import java.util.Collections;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.business.busi.entity.Customer;
import com.business.busi.repository.CustomerRepository;




@Service
public class CustomerService implements UserDetailsService {
	
	@Autowired
	private BCryptPasswordEncoder pwdEncoder;
	
	@Autowired
	private CustomerRepository repository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
//		Customer customer = repository.findByEmail(email);
		Customer customer = repository.findByName(username);
	
//		return new User(customer.getEmail(), customer.getPassword(), Collections.emptyList());
		return new User(customer.getName(), customer.getPassword(), Collections.emptyList());
	}
	
	
	public boolean registerWithCustomer(Customer customer) {
		
		String encodedPassword = pwdEncoder.encode(customer.getPassword());
		customer.setPassword(encodedPassword);
		
		Customer customerData = repository.save(customer);
		
		return customerData.getId() != null;
	}

	

}
