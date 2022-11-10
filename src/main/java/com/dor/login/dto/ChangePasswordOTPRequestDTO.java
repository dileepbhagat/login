package com.dor.login.dto;

public class ChangePasswordOTPRequestDTO extends AbstractRequestDTO {
	
	public String otp;

	public String getOtp() {
		return otp;
	}

	public void setOtp(String otp) {
		this.otp = otp;
	}
	
}
