package com.dor.login.dto;

public class ChangePasswordOTPResponseDTO extends AbstractResponseDTO {
	
	public String otpRef;

	public String getOtpRef() {
		return otpRef;
	}

	public void setOtpRef(String otpRef) {
		this.otpRef = otpRef;
	}

}
