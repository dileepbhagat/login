package com.dor.login.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.dor.login.model.AdminEntity;

public interface AdminRepository extends JpaRepository<AdminEntity, String>{
	
	public AdminEntity findByUserId(String userId);
}

