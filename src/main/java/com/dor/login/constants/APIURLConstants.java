package com.dor.login.constants;

public interface APIURLConstants {
	
	String API_VERSION="/api/v1";
	String LOGIN_GENERATE_OTP="/login/generate/otp";
	String LOGIN_VALIDATE_OTP="/login/validate/otp";
	String USER_LOGOUT="/user/logout";
	String FORGET_PASSWORD_GENERATE_OTP="/forget/password/generate/otp";
	String FORGET_PASSWORD_OTP_VALIDATION="/forget/password/otp/validation";
	String SET_PASSWORD="/set/password";
	String CURRENT_PASSWORD_VALIDATION="/current/password/validation";
	String CHANGE_PASSWORD_OTP_VALIDATION="/change/password/otp/validation";
	String ADD_APP_TO_USER="/add/app/to/user";
	String REMOVE_APP_TO_USER="/remove/app/to/user";
	String APPLICATION_CREATION="/application/creation";
	String USER_CREATION="/user/creation";
	String AUTHENTICATED_USER_LIST_FROM_TODAY="/authenticated/user/list/from/today";
	
	String SEND_OTP="/send/otp";
	String EMAIL_VERIFICATION="/email/verification";
	String MOBILE_VERIFICATION="/mobile/verification";
	String VERIFY_ADMIN_OTP_APPLICATION_CREATION="/verify/admin/otp/application/creation";
	String GET_USER_INFO="/get/user/info";
	
	String AUTHENTICATED_USER_LIST_ON_DAY="/authenticated/user/list/day";
	String AUTHENTICATED_USER_LIST_ON_MONTH="/authenticated/user/list/month";
	String AUTHENTICATED_USER_LIST_ON_YEAR="/authenticated/user/list/year";
	
	String AUTHENTICATED_USER_LIST="/authenticated/user/list";

}
