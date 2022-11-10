package com.dor.login.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.dor.login.model.TokenEntity;

public interface TokenRepository extends JpaRepository<TokenEntity, String>{
	
	public TokenEntity findByLoginId(String loginId);
}
