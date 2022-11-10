package com.dor.login.dto;

public class LoginRequestDTO extends AbstractRequestDTO{
	
	public String otp;
	public Integer appId;

	public String getOtp() {
		return otp;
	}

	public void setOtp(String otp) {
		this.otp = otp;
	}

	public Integer getAppId() {
		return appId;
	}

	public void setAppId(Integer appId) {
		this.appId = appId;
	}

}
