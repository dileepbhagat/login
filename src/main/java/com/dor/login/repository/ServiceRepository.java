package com.dor.login.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.dor.login.model.ServiceEntity;

public interface ServiceRepository extends JpaRepository<ServiceEntity, Integer>{
	
	public ServiceEntity findByServiceName(String serviceName);

}

