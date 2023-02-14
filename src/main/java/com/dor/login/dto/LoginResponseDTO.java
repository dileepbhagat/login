package com.dor.login.dto;

public class LoginResponseDTO extends AbstractResponseDTO{
	
	public String token;
	public Boolean access;

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public Boolean getAccess() {
		return access;
	}

	public void setAccess(Boolean access) {
		this.access = access;
	}

}
