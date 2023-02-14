package com.dor.login.dto;

public class ApplicationResponseDTO extends AbstractResponseDTO {
	
	public Integer appId;
	public String key;
	
	public Integer getAppId() {
		return appId;
	}
	public void setAppId(Integer appId) {
		this.appId = appId;
	}
	public String getKey() {
		return key;
	}
	public void setKey(String key) {
		this.key = key;
	}
	

}
