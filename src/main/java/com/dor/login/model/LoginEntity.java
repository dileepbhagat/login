package com.dor.login.model;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;
import org.hibernate.annotations.TypeDefs;


import io.hypersistence.utils.hibernate.type.array.IntArrayType;
import io.hypersistence.utils.hibernate.type.array.ListArrayType;
import io.hypersistence.utils.hibernate.type.array.StringArrayType;


@Entity
@Table(name="login", schema="login")
@TypeDefs({
    @TypeDef(
        name = "string-array", 
        typeClass = StringArrayType.class
    ),
    @TypeDef(
        name = "int-array", 
        typeClass = IntArrayType.class
    )
})
public class LoginEntity extends BaseEntity{
	@Id
	@Column
	private String loginId;
	
	@Column(name = "user_id")
	private String userId;
	
	@Column(name = "password")
	private String password;
	
	@Column(name = "email_verified")
	private Boolean emailVerified;
	
	@Column(name = "mobile_verified")
	private Boolean mobileVerified;
	
	@Column(name = "otp")
	private String otp;
	
	@Column(name = "otp_request_no")
	private String otpRequestNo;
	
	@Column(name = "otp_timestamp")
	private Timestamp otpTimestamp;
	
	@Column(name = "first_time_password_set")
	private Boolean firstTimePasswordSet;
	
	@Column(name = "email_verified_on")
	private Date emailVerifiedOn;
	
	@Column(name = "created_on")
	private Date createdOn;
	
	@Column(name = "updated_on")
	private Date updatedOn;
	
	@Column(name = "enabled")
	private Boolean enabled;
	
	@Column(name = "last_password_change_time")
	private LocalDateTime lastPasswordChangeTime;
	
	@Column(name = "last_three_passwords")
	private String lastThreePasswords;
	
	@Column(name = "mob_no")
	private String mobNo;
	
	@Column(name = "password_code")
	private String passwordCode;
	
	@Column(name = "updation_type")
	private String updationType;
	
	@Column(name = "last_updation_time")
	private LocalDateTime lastUpdationTime;
	
	@Type(type = "int-array")
    @Column(
        name = "service_access", 
        columnDefinition = "integer[]"
    )
    private int[] serviceAccess;

	public String getPasswordCode() {
		return passwordCode;
	}

	public void setPasswordCode(String passwordCode) {
		this.passwordCode = passwordCode;
	}

	public String getMobNo() {
		return mobNo;
	}

	public void setMobNo(String mobNo) {
		this.mobNo = mobNo;
	}

	public LocalDateTime getLastPasswordChangeTime() {
		return lastPasswordChangeTime;
	}

	public void setLastPasswordChangeTime(LocalDateTime lastPasswordChangeTime) {
		this.lastPasswordChangeTime = lastPasswordChangeTime;
	}

	public String getLastThreePasswords() {
		return lastThreePasswords;
	}

	public void setLastThreePasswords(String lastThreePasswords) {
		this.lastThreePasswords = lastThreePasswords;
	}

	public String getLoginId() {
		return loginId;
	}

	public void setLoginId(String loginId) {
		this.loginId = loginId;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getOtp() {
		return otp;
	}

	public void setOtp(String otp) {
		this.otp = otp;
	}

	public String getOtpRequestNo() {
		return otpRequestNo;
	}

	public void setOtpRequestNo(String otpRequestNo) {
		this.otpRequestNo = otpRequestNo;
	}

	public Timestamp getOtpTimestamp() {
		return otpTimestamp;
	}

	public void setOtpTimestamp(Timestamp otpTimestamp) {
		this.otpTimestamp = otpTimestamp;
	}

	public Date getEmailVerifiedOn() {
		return emailVerifiedOn;
	}

	public void setEmailVerifiedOn(Date emailVerifiedOn) {
		this.emailVerifiedOn = emailVerifiedOn;
	}

	public Boolean getEmailVerified() {
		return emailVerified;
	}

	public void setEmailVerified(Boolean emailVerified) {
		this.emailVerified = emailVerified;
	}

	public Boolean getMobileVerified() {
		return mobileVerified;
	}

	public void setMobileVerified(Boolean mobileVerified) {
		this.mobileVerified = mobileVerified;
	}

	public Boolean getFirstTimePasswordSet() {
		return firstTimePasswordSet;
	}

	public void setFirstTimePasswordSet(Boolean firstTimePasswordSet) {
		this.firstTimePasswordSet = firstTimePasswordSet;
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

	public Boolean getEnabled() {
		return enabled;
	}

	public void setEnabled(Boolean enabled) {
		this.enabled = enabled;
	}

	public String getUpdationType() {
		return updationType;
	}

	public void setUpdationType(String updationType) {
		this.updationType = updationType;
	}

	public LocalDateTime getLastUpdationTime() {
		return lastUpdationTime;
	}

	public void setLastUpdationTime(LocalDateTime lastUpdationTime) {
		this.lastUpdationTime = lastUpdationTime;
	}

	public int[] getServiceAccess() {
		return serviceAccess;
	}

	public void setServiceAccess(int[] serviceAccess) {
		this.serviceAccess = serviceAccess;
	}
	
}

