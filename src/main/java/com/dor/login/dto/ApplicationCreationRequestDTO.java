package com.dor.login.dto;

public class ApplicationCreationRequestDTO {
	
	public String appName;
	public String appShortCode;
	public String adminMob;
	public String adminEmail;
	
	public String getAppName() {
		return appName;
	}
	public void setAppName(String appName) {
		this.appName = appName;
	}
	public String getAppShortCode() {
		return appShortCode;
	}
	public void setAppShortCode(String appShortCode) {
		this.appShortCode = appShortCode;
	}
	public String getAdminMob() {
		return adminMob;
	}
	public void setAdminMob(String adminMob) {
		this.adminMob = adminMob;
	}
	public String getAdminEmail() {
		return adminEmail;
	}
	public void setAdminEmail(String adminEmail) {
		this.adminEmail = adminEmail;
	}

}
