package com.dor.login.dto;

public class SendOTPRequestDTO {
	
	public String appShortCode;
	public String emailId;
	public String appName;
	public String mobNo;
	public String getAppShortCode() {
		return appShortCode;
	}
	public void setAppShortCode(String appShortCode) {
		this.appShortCode = appShortCode;
	}
	public String getEmailId() {
		return emailId;
	}
	public void setEmailId(String emailId) {
		this.emailId = emailId;
	}
	
	public String getAppName() {
		return appName;
	}
	public void setAppName(String appName) {
		this.appName = appName;
	}
	public String getMobNo() {
		return mobNo;
	}
	public void setMobNo(String mobNo) {
		this.mobNo = mobNo;
	}

}
