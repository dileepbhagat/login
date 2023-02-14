package com.dor.login.repository;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.dor.login.model.APIRequestEntity;

public interface APIRequestRepository extends JpaRepository<APIRequestEntity, Integer>{
	
	public List<APIRequestEntity> findByLoginId(String loginId);

}
