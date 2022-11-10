package com.dor.login.dto;

public class LoginResponseDTO extends AbstractResponseDTO{
	
	public String token;

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

}
