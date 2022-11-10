package com.dor.login.repository;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.dor.login.model.AuthenticationLogEntity;

public interface AuthenticationLogRepository extends JpaRepository<AuthenticationLogEntity, Integer>{
	
	public AuthenticationLogEntity findByLoginIdAndStatus(String loginId, Boolean status);
	public List<AuthenticationLogEntity> findByLoginId(String loginId);
	//authenticated user list
	public List<AuthenticationLogEntity> findByAuthenticatedAndAuthenticatedApp(Boolean authenticated, Integer authenticatedApp);
	// counting the frequency of users
	public long countByLoginIdAndAuthenticatedAndAuthenticatedApp(String loginId, Boolean authenticated, Integer authenticatedApp);
	
	//@Query(value="SELECT * FROM login.authentication_log u WHERE u.authenticated = true AND u.authenticated_app= :appId AND u.authenticated_on BETWEEN :date2 AND :date1", nativeQuery = true)
	//List<AuthenticationLogEntity> findAllAuthenticatedUsersFromToday(@Param("date1") String date1, @Param("date2") String date2, @Param("appId") Integer appId) ;
	
	
	public List<AuthenticationLogEntity> findByAuthenticatedEqualsAndAuthenticatedAppEqualsAndAuthenticatedOnLessThanAndAuthenticatedOnGreaterThanEqual(Boolean status, Integer authenticatedApp, String date1, String date2);
	
	@Query(value="SELECT * FROM login.authentication_log u WHERE u.authenticated = true AND u.authenticated_app= :appId AND u.authenticated_timestamp BETWEEN :date1 AND :date2", nativeQuery = true)
	List<AuthenticationLogEntity> findAllAuthenticatedUsers(@Param("date1") LocalDateTime date1, @Param("date2") LocalDateTime date2, @Param("appId") Integer appId);
	
	@Query(value="SELECT * FROM login.authentication_log u WHERE u.authenticated = true AND u.authenticated_app= :appId AND u.authenticated_timestamp BETWEEN :date1 AND :date2", nativeQuery = true)
	List<AuthenticationLogEntity> findAllAuthenticatedUsersOnDay(@Param("date1") LocalDateTime date1, @Param("date2") LocalDateTime date2, @Param("appId") Integer appId);
	
	@Query(value="SELECT * FROM login.authentication_log u WHERE u.authenticated = true AND u.authenticated_app= :appId AND u.authenticated_timestamp BETWEEN :date1 AND :date2", nativeQuery = true)
	List<AuthenticationLogEntity> findAllAuthenticatedUsersOnMonth(@Param("date1") LocalDateTime date1, @Param("date2") LocalDateTime date2, @Param("appId") Integer appId);
	
	@Query(value="SELECT * FROM login.authentication_log u WHERE u.authenticated = true AND u.authenticated_app= :appId AND u.authenticated_timestamp BETWEEN :date1 AND :date2", nativeQuery = true)
	List<AuthenticationLogEntity> findAllAuthenticatedUsersOnYear(@Param("date1") LocalDateTime date1, @Param("date2") LocalDateTime date2, @Param("appId") Integer appId);
	
	@Query(value="SELECT l.login_id FROM login.login l EXCEPT SELECT distinct u.login_id FROM login.authentication_log u WHERE u.authenticated = true AND u.authenticated_app= :appId AND u.authenticated_timestamp BETWEEN :date1 AND :date2", nativeQuery = true)
	List<String> findAllUnAuthenticatedUsers(@Param("date1") LocalDateTime date1, @Param("date2") LocalDateTime date2, @Param("appId") Integer appId);
}


