package com.dor.login.repository;
import org.springframework.data.jpa.repository.JpaRepository;

import com.dor.login.model.LoginEntity;

public interface LoginRepository extends JpaRepository<LoginEntity, String>{
	
	public LoginEntity findByUserId(String userId);
	public void deleteByUserId(String userId);
	public LoginEntity findByLoginId(String loginId);
	public LoginEntity findByPasswordCode(String passwordCode);
}
