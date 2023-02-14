package com.dor.login.service;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.dor.login.model.LoginEntity;
import com.dor.login.repository.LoginRepository;

@Service
public class JwtUserDetailsService implements UserDetailsService {

	@Autowired
	private LoginRepository loginRepository;
	
	@Override
	public UserDetails loadUserByUsername(String loginId) throws UsernameNotFoundException {
		LoginEntity loginEntity = loginRepository.findByLoginId(loginId);
		if (loginEntity == null) {
			throw new UsernameNotFoundException("User not found with loginId: " + loginId);
		}
		else
		{
			String password=loginEntity.getPassword();
			return new org.springframework.security.core.userdetails.User(loginId, new BCryptPasswordEncoder().encode(password),
					new ArrayList<>());
		}
		
	}
	
}

