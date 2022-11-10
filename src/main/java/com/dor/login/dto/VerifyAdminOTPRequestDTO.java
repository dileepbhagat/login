package com.dor.login.dto;

public class VerifyAdminOTPRequestDTO {
	
	public String appShortCode;
	public String emailId;
	public String appName;
	public String mobNo;
	public String fileName;
	public String adminOtp;
	
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
	public String getFileName() {
		return fileName;
	}
	public void setFileName(String fileName) {
		this.fileName = fileName;
	}
	public String getAdminOtp() {
		return adminOtp;
	}
	public void setAdminOtp(String adminOtp) {
		this.adminOtp = adminOtp;
	}

}
