package com.dor.login.dto;

public class LoginOTPResponseDTO extends AbstractResponseDTO {
	
	public String otpRef;
	public Integer appId;

	public String getOtpRef() {
		return otpRef;
	}

	public void setOtpRef(String otpRef) {
		this.otpRef = otpRef;
	}

	public Integer getAppId() {
		return appId;
	}

	public void setAppId(Integer appId) {
		this.appId = appId;
	}

}
