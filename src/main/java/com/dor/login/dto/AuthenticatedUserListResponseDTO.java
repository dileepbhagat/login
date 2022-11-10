package com.dor.login.dto;

import java.util.List;

public class AuthenticatedUserListResponseDTO {
	
	public List<AuthenticatedUser> authenticatedUserList;
	public List<AuthenticatedUser> authenticatedTopUserList;
	public List<AuthenticatedUser> authenticatedBottomUserList;
	public List<AuthenticatedUser> unAuthenticatedUserList;
	public Boolean status;
	public String msg;
	
	public List<AuthenticatedUser> getAuthenticatedUserList() {
		return authenticatedUserList;
	}

	public void setAuthenticatedUserList(List<AuthenticatedUser> authenticatedUserList) {
		this.authenticatedUserList = authenticatedUserList;
	}

	public Boolean getStatus() {
		return status;
	}

	public void setStatus(Boolean status) {
		this.status = status;
	}

	public String getMsg() {
		return msg;
	}

	public void setMsg(String msg) {
		this.msg = msg;
	}

	public List<AuthenticatedUser> getAuthenticatedTopUserList() {
		return authenticatedTopUserList;
	}

	public void setAuthenticatedTopUserList(List<AuthenticatedUser> authenticatedTopUserList) {
		this.authenticatedTopUserList = authenticatedTopUserList;
	}

	public List<AuthenticatedUser> getAuthenticatedBottomUserList() {
		return authenticatedBottomUserList;
	}

	public void setAuthenticatedBottomUserList(List<AuthenticatedUser> authenticatedBottomUserList) {
		this.authenticatedBottomUserList = authenticatedBottomUserList;
	}

	public List<AuthenticatedUser> getUnAuthenticatedUserList() {
		return unAuthenticatedUserList;
	}

	public void setUnAuthenticatedUserList(List<AuthenticatedUser> unAuthenticatedUserList) {
		this.unAuthenticatedUserList = unAuthenticatedUserList;
	}
	
}
