package com.dor.login.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.dor.login.model.UserApplicationEntity;

public interface UserApplicationRepository extends JpaRepository<UserApplicationEntity, Integer>{
	
	public UserApplicationEntity findByLoginIdAndAppIdAndEnabled(String loginId, Integer appId, Boolean enabled);
	public void deleteByLoginIdAndAppId(String loginId, Integer appId);

}