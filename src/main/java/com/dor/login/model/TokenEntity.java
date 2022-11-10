package com.dor.login.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name="token", schema="login")

public class TokenEntity {
	
	@Id
	@Column(name="login_id")
	private String loginId;
	
	@Column(name="token")
	private String token;
	
	@Column(name = "token_expired")
	private Boolean tokenExpired;
	
	@Column(name = "token_exp_timestamp")
	private Long tokenExpTimestamp;

	public Long getTokenExpTimestamp() {
		return tokenExpTimestamp;
	}

	public void setTokenExpTimestamp(Long tokenExpTimestamp) {
		this.tokenExpTimestamp = tokenExpTimestamp;
	}

	public String getLoginId() {
		return loginId;
	}

	public void setLoginId(String loginId) {
		this.loginId = loginId;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public Boolean getTokenExpired() {
		return tokenExpired;
	}

	public void setTokenExpired(Boolean tokenExpired) {
		this.tokenExpired = tokenExpired;
	}

}
