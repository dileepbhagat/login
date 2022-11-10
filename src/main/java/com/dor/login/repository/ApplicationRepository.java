package com.dor.login.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.dor.login.model.ApplicationEntity;

public interface ApplicationRepository extends JpaRepository<ApplicationEntity, Integer>{
	
	public ApplicationEntity findByAppId(Integer appId);
	public ApplicationEntity findByKey(String key);

}
