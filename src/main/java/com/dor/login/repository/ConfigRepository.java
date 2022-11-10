package com.dor.login.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.dor.login.model.ConfigEntity;

public interface ConfigRepository extends JpaRepository<ConfigEntity, Integer>{
	
	public ConfigEntity findByUserType(String userType);
}
