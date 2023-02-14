package com.dor.login.controller;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.configurationprocessor.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.dor.login.model.TokenEntity;
import com.dor.login.repository.TokenRepository;
import com.dor.login.constants.APIConstants;
import com.dor.login.constants.APIURLConstants;
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
import com.dor.login.service.JWTUserTokenGenerationService;
import com.dor.login.service.LoginService;

//@CrossOrigin(origins = "http://localhost:4300")
@CrossOrigin(origins = "*")
@RestController
@RequestMapping(APIURLConstants.API_VERSION)
public class LoginController {
	
	@Autowired
	private LoginService loginService;
	
	@Autowired
	private JWTUserTokenGenerationService jwtUserTokenGenerationService;
	
	@Autowired
	private TokenRepository tokenRepository;
	
	@PostMapping(APIURLConstants.LOGIN_GENERATE_OTP)
	public ResponseEntity<LoginOTPResponseDTO> loginGenerateOTP(@Validated @RequestBody AbstractRequestDTO requestDTO) throws Exception
	{
		LoginOTPResponseDTO responseDTO=new LoginOTPResponseDTO();
		responseDTO=loginService.loginGenerateOTP(requestDTO);
		if(responseDTO.getStatus()==true)
		{
			return ResponseEntity.ok(responseDTO);
		}
		else
			return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE);
	}
	
	
	@PostMapping(APIURLConstants.LOGIN_VALIDATE_OTP)
	public ResponseEntity<LoginResponseDTO> loginValidateOTP(@Validated @RequestBody LoginRequestDTO requestDTO, HttpServletRequest httpServletRequest) throws Exception
	{
		String ipAddress=httpServletRequest.getRemoteAddr();
		LoginResponseDTO responseDTO=new LoginResponseDTO();
		responseDTO=loginService.loginValidateOTP(requestDTO,ipAddress);
		if(responseDTO.getStatus()==true)
		{
			String securedPassword=generateSHA256SecuredPassword(requestDTO.getPassword());
			String token=jwtUserTokenGenerationService.generateTokenByUsername(requestDTO.getLoginId(),securedPassword);
			TokenEntity tokenEntity=null;
			tokenEntity=tokenRepository.findByLoginId(requestDTO.getLoginId());
			Long exp=findTokenExpiration(token);
			if(tokenEntity!=null)
			{
				tokenEntity.setTokenExpired(false);
				tokenEntity.setToken(token);
				tokenEntity.setTokenExpTimestamp(exp);
			}
			else
			{
				tokenEntity=new TokenEntity();
				tokenEntity.setTokenExpired(false);
				tokenEntity.setLoginId(requestDTO.getLoginId());
				tokenEntity.setToken(token);
				// finding the token expiration timestamp
				tokenEntity.setTokenExpTimestamp(exp);
			}
			responseDTO.setToken(token);
			tokenRepository.save(tokenEntity);
			return ResponseEntity.ok(responseDTO);
		}
		else
			return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE);
	}
	
	@PostMapping(APIURLConstants.USER_LOGOUT)
	public ResponseEntity<AbstractResponseDTO> userLogout(@Validated @RequestBody AbstractRequestDTO requestDTO) throws Exception
	{
		AbstractResponseDTO responseDTO=new AbstractResponseDTO();
		responseDTO=loginService.userLogout(requestDTO);
		if(responseDTO.getStatus()==true)
		{
			return ResponseEntity.ok(responseDTO);
		}
		else
			return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE);
	}
	
	@PostMapping(APIURLConstants.FORGET_PASSWORD_GENERATE_OTP)
	public ResponseEntity<ForgetPasswordOTPResponseDTO> forgetPasswordGenerateOTP(@Validated @RequestBody AbstractRequestDTO requestDTO) throws Exception
	{
		ForgetPasswordOTPResponseDTO responseDTO=new ForgetPasswordOTPResponseDTO();
		responseDTO=loginService.forgetPasswordGenerateOTP(requestDTO);
		if(responseDTO.getStatus()==true)
		{
			return ResponseEntity.ok(responseDTO);
		}
		else
			return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE);
	}
	
	@PostMapping(APIURLConstants.FORGET_PASSWORD_OTP_VALIDATION)
	public ResponseEntity<ForgetPasswordOTPValidationResponseDTO> forgetPasswordOTPValidation(@Validated @RequestBody ForgetPasswordOTPRequestDTO requestDTO) throws Exception
	{
		ForgetPasswordOTPValidationResponseDTO responseDTO=new ForgetPasswordOTPValidationResponseDTO();
		responseDTO=loginService.forgetPasswordOTPValidation(requestDTO);
		if(responseDTO.getStatus()==true)
		{
			return ResponseEntity.ok(responseDTO);
		}
		else
			return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE);
	}
	
	@PostMapping(APIURLConstants.SET_PASSWORD)  //@RequestParam
	public ResponseEntity<AbstractResponseDTO> setPassword(@RequestParam String key, @RequestParam String password) throws Exception
	{
		AbstractResponseDTO responseDTO=new AbstractResponseDTO();
		SetPasswordRequestDTO requestDTO=new SetPasswordRequestDTO(key,password);
		responseDTO=loginService.setPassword(requestDTO);
		if(responseDTO.getStatus()==true)
		{
			return ResponseEntity.ok(responseDTO);
		}
		else
			return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE);
	}
	
	@PostMapping(APIURLConstants.CURRENT_PASSWORD_VALIDATION)
	public ResponseEntity<ChangePasswordOTPResponseDTO> currentPasswordValidation(@Validated @RequestBody AbstractRequestDTO requestDTO) throws Exception
	{
		ChangePasswordOTPResponseDTO responseDTO=new ChangePasswordOTPResponseDTO();
		responseDTO=loginService.currentPasswordValidation(requestDTO);
		if(responseDTO.getStatus()==true)
		{
			return ResponseEntity.ok(responseDTO);
		}
		else
			return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE);
	}
	
	@PostMapping(APIURLConstants.CHANGE_PASSWORD_OTP_VALIDATION)
	public ResponseEntity<ChangePasswordOTPValidationResponseDTO> changePasswordOTPValidation(@Validated @RequestBody ChangePasswordOTPRequestDTO requestDTO) throws Exception
	{
		ChangePasswordOTPValidationResponseDTO responseDTO=new ChangePasswordOTPValidationResponseDTO();
		responseDTO=loginService.changePasswordOTPValidation(requestDTO);
		if(responseDTO.getStatus()==true)
		{
			return ResponseEntity.ok(responseDTO);
		}
		else
			return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE);
	}
	
	/*
	 * @PostMapping(APIURLConstants.SEND_OTP) public
	 * ResponseEntity<SendOTPResponseDTO> sendOTP(@Validated @RequestBody
	 * SendOTPRequestDTO requestDTO) throws Exception { SendOTPResponseDTO
	 * responseDTO=new SendOTPResponseDTO();
	 * responseDTO=loginService.sendOTP(requestDTO);
	 * if(responseDTO.getStatus()==true) { return ResponseEntity.ok(responseDTO); }
	 * else return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE); }
	 */
	
	@PostMapping(APIURLConstants.EMAIL_VERIFICATION)  //@RequestParam
	public ResponseEntity<LoginOTPResponseDTO> emailVerification(@RequestParam String key) throws Exception
	{
		LoginOTPResponseDTO responseDTO=new LoginOTPResponseDTO();
		responseDTO=loginService.emailVerification(key);
		if(responseDTO.getStatus()==true)
		{
			return ResponseEntity.ok(responseDTO);
		}
		else
			return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE);
	}
	
	
	@PostMapping(APIURLConstants.MOBILE_VERIFICATION)  //@RequestParam
	public ResponseEntity<AbstractResponseDTO> mobileVerification(@Validated @RequestBody MobileVerificationRequestDTO requestDTO) throws Exception
	{
		AbstractResponseDTO responseDTO=new AbstractResponseDTO();
		responseDTO=loginService.mobileVerification(requestDTO);
		if(responseDTO.getStatus()==true)
		{
			return ResponseEntity.ok(responseDTO);
		}
		else
			return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE);
	}
	
	// This API is for admin usuage
	@PostMapping(APIURLConstants.ADD_APP_TO_USER)
	public ResponseEntity<AbstractResponseDTO> addAppToUser(@Validated @RequestBody AddRemoveApplRequestDTO requestDTO) throws Exception
	{
		AbstractResponseDTO responseDTO=new AbstractResponseDTO();
		responseDTO=loginService.addAppToUser(requestDTO);
		if(responseDTO.getStatus()==true)
		{
			return ResponseEntity.ok(responseDTO);
		}
		else
			return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE);
	}
	
	// This API is for admin usuage
	@PostMapping(APIURLConstants.REMOVE_APP_TO_USER)
	public ResponseEntity<AbstractResponseDTO> removeAppToUser(@Validated @RequestBody AddRemoveApplRequestDTO requestDTO) throws Exception
	{
		AbstractResponseDTO responseDTO=new AbstractResponseDTO();
		responseDTO=loginService.removeAppToUser(requestDTO);
		if(responseDTO.getStatus()==true)
		{
			return ResponseEntity.ok(responseDTO);
		}
		else
			return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE);
	}
	
	// This API is for admin usuage
	@PostMapping(APIURLConstants.APPLICATION_CREATION)
	public ResponseEntity<LoginOTPResponseDTO> createApplication(@Validated @RequestBody ApplicationCreationRequestDTO requestDTO) throws Exception
	{
		LoginOTPResponseDTO responseDTO=new LoginOTPResponseDTO();
		responseDTO=loginService.createApplication(requestDTO);
		if(responseDTO.getStatus()==true)
		{
			return ResponseEntity.ok(responseDTO);
		}
		else
			return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE);
	}
	
	// This API is for admin usuage
	@PostMapping(APIURLConstants.VERIFY_ADMIN_OTP_APPLICATION_CREATION)
	public ResponseEntity<AbstractResponseDTO> verifyAdminOTPAndCreateApplication(@Validated @RequestBody VerifyAdminOTPRequestDTO requestDTO) throws Exception
	{
		AbstractResponseDTO responseDTO=new AbstractResponseDTO();
		responseDTO=loginService.verifyAdminOTPAndCreateApplication(requestDTO);
		if(responseDTO.getStatus()==true)
		{
			return ResponseEntity.ok(responseDTO);
		}
		else
			return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE);
	}
	
	// This API is for admin usuage
	@PostMapping(APIURLConstants.GET_USER_INFO)  //@RequestParam
	public ResponseEntity<UserInfoResponseDTO> getUserInfo(@RequestParam String key) throws Exception
	{
		UserInfoResponseDTO responseDTO=new UserInfoResponseDTO();
		responseDTO=loginService.getUserInfo(key);
		if(responseDTO.getStatus()==true)
		{
			return ResponseEntity.ok(responseDTO);
		}
		else
			return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE);
	}
	
	
	// This API is for admin usuage
	@PostMapping(APIURLConstants.USER_CREATION)
	public ResponseEntity<AbstractResponseDTO> createUser(@Validated @RequestBody UserCreationRequestDTO requestDTO) throws Exception
	{
		AbstractResponseDTO responseDTO=new AbstractResponseDTO();
		responseDTO=loginService.createUser(requestDTO);
		if(responseDTO.getStatus()==true)
		{
			return ResponseEntity.ok(responseDTO);
		}
		else
			return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE);
	}
	
	// Follwing APIs returns authenticated users list day, month & year wise
	@PostMapping(APIURLConstants.AUTHENTICATED_USER_LIST)
	public ResponseEntity<AuthenticatedUserListResponseDTO> authenticatedUserListFromToday(@Validated @RequestBody AuthenticatedUserListRequestDTO requestDTO) throws Exception
	{
		AuthenticatedUserListResponseDTO responseDTO=new AuthenticatedUserListResponseDTO();
		responseDTO=loginService.authenticatedUserList(requestDTO);
		if(responseDTO.getStatus()==true)
		{
			return ResponseEntity.ok(responseDTO);
		}
		else
			return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE);
	}
	
	
	/*
	 * @GetMapping(APIURLConstants.AUTHENTICATED_USER_LIST_ON_DAY) public
	 * ResponseEntity<AuthenticatedUserListResponseDTO>
	 * authenticatedUserListOnDay(@Validated @RequestBody
	 * AuthenticatedUserListRequestDTO requestDTO) throws Exception {
	 * AuthenticatedUserListResponseDTO responseDTO=new
	 * AuthenticatedUserListResponseDTO(); if(requestDTO.getDaywise()==true &&
	 * requestDTO.getDay()!=null && requestDTO.getMonth()!=null &&
	 * requestDTO.getYear()!=null && requestDTO.getDay()!="" &&
	 * requestDTO.getMonth()!="" && requestDTO.getYear()!="") {
	 * responseDTO=loginService.authenticatedUserListOnDay(requestDTO);
	 * if(responseDTO.getStatus()==true) { return ResponseEntity.ok(responseDTO); }
	 * else return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE); }
	 * else return new ResponseEntity<>(responseDTO, HttpStatus.BAD_REQUEST);
	 * 
	 * }
	 * 
	 * 
	 * @GetMapping(APIURLConstants.AUTHENTICATED_USER_LIST_ON_MONTH) public
	 * ResponseEntity<AuthenticatedUserListResponseDTO>
	 * authenticatedUserListOnMonth(@Validated @RequestBody
	 * AuthenticatedUserListRequestDTO requestDTO) throws Exception {
	 * AuthenticatedUserListResponseDTO responseDTO=new
	 * AuthenticatedUserListResponseDTO(); if(requestDTO.getMonthwise()==true &&
	 * requestDTO.getMonth()!=null && requestDTO.getMonth()!="" &&
	 * requestDTO.getYear()!=null && requestDTO.getYear()!="") {
	 * responseDTO=loginService.authenticatedUserListOnMonth(requestDTO);
	 * if(responseDTO.getStatus()==true) { return ResponseEntity.ok(responseDTO); }
	 * else return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE); }
	 * else return new ResponseEntity<>(responseDTO, HttpStatus.BAD_REQUEST);
	 * 
	 * }
	 * 
	 * 
	 * @GetMapping(APIURLConstants.AUTHENTICATED_USER_LIST_ON_YEAR) public
	 * ResponseEntity<AuthenticatedUserListResponseDTO>
	 * authenticatedUserListOnYear(@Validated @RequestBody
	 * AuthenticatedUserListRequestDTO requestDTO) throws Exception {
	 * AuthenticatedUserListResponseDTO responseDTO=new
	 * AuthenticatedUserListResponseDTO(); if(requestDTO.getYearwise()==true &&
	 * requestDTO.getYear()!=null && requestDTO.getYear()!="") {
	 * responseDTO=loginService.authenticatedUserListOnYear(requestDTO);
	 * if(responseDTO.getStatus()==true) { return ResponseEntity.ok(responseDTO); }
	 * else return new ResponseEntity<>(responseDTO, HttpStatus.NOT_ACCEPTABLE); }
	 * else return new ResponseEntity<>(responseDTO, HttpStatus.BAD_REQUEST);
	 * 
	 * }
	 */
	
	
	
	private static String generateSHA256SecuredPassword(String passwordToHash) {
        String generatedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(APIConstants.SALT.getBytes());
            byte[] bytes = md.digest(passwordToHash.getBytes());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16)
                        .substring(1));
            }
            generatedPassword = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return generatedPassword;
    }
	
	public Long findTokenExpiration(String token)
	{
		String[] parts = token.split("\\.");
		try
		{
			JSONObject header = new JSONObject(decode(parts[0]));
			JSONObject payload = new JSONObject(decode(parts[1]));
			String signature = decode(parts[2]);
			return payload.getLong("exp"); 
		}
		catch(Exception e)
		{ }
		return null;
	}
	
	private static String decode(String encodedString) {
	    return new String(Base64.getUrlDecoder().decode(encodedString));
	}

}
