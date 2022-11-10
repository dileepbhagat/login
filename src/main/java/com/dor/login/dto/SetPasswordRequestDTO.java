package com.dor.login.dto;

public class SetPasswordRequestDTO {
	
	public String key;
	public String password;
	
	public SetPasswordRequestDTO(String key, String password) {
		super();
		this.key = key;
		this.password = password;
	}
	public String getKey() {
		return key;
	}
	public void setKey(String key) {
		this.key = key;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}

}
