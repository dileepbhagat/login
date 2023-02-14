package com.dor.login.model;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name="config", schema="login")

public class ConfigEntity {
	
	@Id
	@Column(name="serial_no")
	@GeneratedValue(strategy=GenerationType.IDENTITY)
	private Integer serialNo;
	
	@Column(name="user_type")
	private String userType;
	
	@Column(name="session_out_time_in_min")
	private Integer sessionOutTimeInMin;
	
	@Column(name = "otp_expire_time_in_min")
	private Integer otpExpireTimeInMin;
	
	@Column(name = "created_on")
	private Date createdOn;
	
	@Column(name = "updated_on")
	private Date updatedOn;
	
	@Column(name = "password_change_policy_time_in_days")
	private Integer passwordChangePolicyTimeInDays;
	
	@Column(name = "email_verification_duration_in_hours")
	private Integer emailVerificationDurationInHours;
	
	public String getUserType() {
		return userType;
	}

	public void setUserType(String userType) {
		this.userType = userType;
	}

	public Integer getSerialNo() {
		return serialNo;
	}

	public void setSerialNo(Integer serialNo) {
		this.serialNo = serialNo;
	}

	public Integer getSessionOutTimeInMin() {
		return sessionOutTimeInMin;
	}

	public void setSessionOutTimeInMin(Integer sessionOutTimeInMin) {
		this.sessionOutTimeInMin = sessionOutTimeInMin;
	}

	public Integer getOtpExpireTimeInMin() {
		return otpExpireTimeInMin;
	}

	public void setOtpExpireTimeInMin(Integer otpExpireTimeInMin) {
		this.otpExpireTimeInMin = otpExpireTimeInMin;
	}

	public Date getCreatedOn() {
		return createdOn;
	}

	public void setCreatedOn(Date createdOn) {
		this.createdOn = createdOn;
	}

	public Date getUpdatedOn() {
		return updatedOn;
	}

	public void setUpdatedOn(Date updatedOn) {
		this.updatedOn = updatedOn;
	}

	public Integer getPasswordChangePolicyTimeInDays() {
		return passwordChangePolicyTimeInDays;
	}

	public void setPasswordChangePolicyTimeInDays(Integer passwordChangePolicyTimeInDays) {
		this.passwordChangePolicyTimeInDays = passwordChangePolicyTimeInDays;
	}

	public Integer getEmailVerificationDurationInHours() {
		return emailVerificationDurationInHours;
	}

	public void setEmailVerificationDurationInHours(Integer emailVerificationDurationInHours) {
		this.emailVerificationDurationInHours = emailVerificationDurationInHours;
	}

}

