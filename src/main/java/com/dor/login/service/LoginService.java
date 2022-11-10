package com.dor.login.service;

import com.dor.login.dto.AbstractRequestDTO;
import com.dor.login.dto.AbstractResponseDTO;
import com.dor.login.dto.AddRemoveApplRequestDTO;
import com.dor.login.dto.ApplicationCreationRequestDTO;
import com.dor.login.dto.ApplicationResponseDTO;
import com.dor.login.dto.AuthenticatedUserListRequestDTO;
import com.dor.login.dto.AuthenticatedUserListResponseDTO;
import com.dor.login.dto.ChangePasswordOTPRequestDTO;
import com.dor.login.dto.ChangePasswordOTPResponseDTO;
import com.dor.login.dto.ChangePasswordOTPValidationResponseDTO;
import com.dor.login.dto.ForgetPasswordOTPRequestDTO;
import com.dor.login.dto.ForgetPasswordOTPResponseDTO;
import com.dor.login.dto.ForgetPasswordOTPValidationResponseDTO;
import com.dor.login.dto.LoginOTPResponseDTO;
import com.dor.login.dto.LoginRequestDTO;
import com.dor.login.dto.LoginResponseDTO;
import com.dor.login.dto.MobileVerificationRequestDTO;
import com.dor.login.dto.SendOTPRequestDTO;
import com.dor.login.dto.SendOTPResponseDTO;
import com.dor.login.dto.SetPasswordRequestDTO;
import com.dor.login.dto.UserCreationRequestDTO;
import com.dor.login.dto.UserInfoResponseDTO;
import com.dor.login.dto.VerifyAdminOTPRequestDTO;

public interface LoginService {
	
	public LoginOTPResponseDTO loginGenerateOTP(AbstractRequestDTO requestDTO) throws Exception;
	public LoginResponseDTO loginValidateOTP(LoginRequestDTO requestDTO, String ipAddress) throws Exception;
	public AbstractResponseDTO userLogout(AbstractRequestDTO requestDTO) throws Exception;
	public ForgetPasswordOTPResponseDTO forgetPasswordGenerateOTP(AbstractRequestDTO requestDTO) throws Exception;
	public ForgetPasswordOTPValidationResponseDTO forgetPasswordOTPValidation(ForgetPasswordOTPRequestDTO requestDTO) throws Exception;
	public AbstractResponseDTO setPassword(SetPasswordRequestDTO setPasswordRequestDTO) throws Exception;
	public ChangePasswordOTPResponseDTO currentPasswordValidation(AbstractRequestDTO requestDTO) throws Exception;
	public ChangePasswordOTPValidationResponseDTO changePasswordOTPValidation(ChangePasswordOTPRequestDTO requestDTO) throws Exception;
	public AbstractResponseDTO addAppToUser(AddRemoveApplRequestDTO requestDTO) throws Exception;
	public AbstractResponseDTO removeAppToUser(AddRemoveApplRequestDTO requestDTO) throws Exception;
	public LoginOTPResponseDTO createApplication(ApplicationCreationRequestDTO requestDTO) throws Exception;
	public AbstractResponseDTO createUser(UserCreationRequestDTO requestDTO) throws Exception;
	public SendOTPResponseDTO sendOTP(SendOTPRequestDTO requestDTO) throws Exception;
	public LoginOTPResponseDTO emailVerification(String key) throws Exception;
	public AbstractResponseDTO verifyAdminOTPAndCreateApplication(VerifyAdminOTPRequestDTO requestDTO) throws Exception;
	public AbstractResponseDTO mobileVerification(MobileVerificationRequestDTO requestDTO) throws Exception;
	public UserInfoResponseDTO getUserInfo(String key) throws Exception;
	public AuthenticatedUserListResponseDTO authenticatedUserList(AuthenticatedUserListRequestDTO requestDTO) throws Exception;
	public AuthenticatedUserListResponseDTO authenticatedUserListOnDay(AuthenticatedUserListRequestDTO requestDTO) throws Exception;
	public AuthenticatedUserListResponseDTO authenticatedUserListOnMonth(AuthenticatedUserListRequestDTO requestDTO) throws Exception;
	public AuthenticatedUserListResponseDTO authenticatedUserListOnYear(AuthenticatedUserListRequestDTO requestDTO) throws Exception;
	
}
