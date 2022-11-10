package com.dor.login.dto;

import java.io.Serializable;

public class JwtRequest implements Serializable {

	private static final long serialVersionUID = 1L;
	
	private String loginId;
	private String password;
	
	//need default constructor for JSON Parsing
	public JwtRequest()
	{
		
	}

	public JwtRequest(String loginId, String password) {
		super();
		this.loginId = loginId;
		this.password = password;
	}

	public String getLoginId() {
		return loginId;
	}



	public void setLoginId(String loginId) {
		this.loginId = loginId;
	}



	public String getPassword() {
		return this.password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
}

