package com.dor.login.dto;

public class UserInfoResponseDTO extends AbstractResponseDTO {
	
	public String userId;
	public Integer appId;
	public String appShortCode;
	public String key;
	
	public String getUserId() {
		return userId;
	}
	public void setUserId(String userId) {
		this.userId = userId;
	}
	public Integer getAppId() {
		return appId;
	}
	public void setAppId(Integer appId) {
		this.appId = appId;
	}
	public String getAppShortCode() {
		return appShortCode;
	}
	public void setAppShortCode(String appShortCode) {
		this.appShortCode = appShortCode;
	}
	public String getKey() {
		return key;
	}
	public void setKey(String key) {
		this.key = key;
	}

}
