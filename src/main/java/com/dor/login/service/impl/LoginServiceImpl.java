package com.dor.login.service.impl;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.Multipart;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.dor.login.model.APIRequestEntity;
import com.dor.login.model.ApplicationEntity;
import com.dor.login.model.ConfigEntity;
import com.dor.login.model.TokenEntity;
import com.dor.login.model.UserApplicationEntity;
import com.dor.login.constants.APIConstants;
import com.dor.login.dto.AbstractRequestDTO;
import com.dor.login.dto.AbstractResponseDTO;
import com.dor.login.dto.AddRemoveApplRequestDTO;
import com.dor.login.dto.ApplicationCreationRequestDTO;
import com.dor.login.dto.ApplicationResponseDTO;
import com.dor.login.dto.AuthenticatedUser;
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
import com.dor.login.dto.UnAuthenticatedUser;
import com.dor.login.dto.UserCreationRequestDTO;
import com.dor.login.dto.UserInfoResponseDTO;
import com.dor.login.dto.VerifyAdminOTPRequestDTO;
import com.dor.login.mapping.ObjectToJsonMapper;
import com.dor.login.model.LoginEntity;
import com.dor.login.model.ServiceEntity;
import com.dor.login.model.AuthenticationLogEntity;
import com.dor.login.repository.APIRequestRepository;
import com.dor.login.repository.ApplicationRepository;
import com.dor.login.repository.ConfigRepository;
import com.dor.login.repository.AuthenticationLogRepository;
import com.dor.login.repository.LoginRepository;
import com.dor.login.repository.ServiceRepository;
import com.dor.login.repository.TokenRepository;
import com.dor.login.repository.UserApplicationRepository;
import com.dor.login.service.LoginService;
import com.twilio.Twilio;
import com.twilio.type.PhoneNumber;
import java.time.format.DateTimeFormatter;

@Service
public class LoginServiceImpl implements LoginService{

	@Autowired
	private LoginRepository loginRepository;
	
	@Autowired
	private AuthenticationLogRepository authenticationLogRepository;
	
	@Autowired
	private ConfigRepository configRepository;
	
	@Autowired
	private TokenRepository tokenRepository;
	
	@Autowired
	private ApplicationRepository applicationRepository;
	
	@Autowired
	private ServiceRepository serviceRepository;
	
	@Autowired
	private UserApplicationRepository userApplicationRepository;
	
	@Autowired
	private APIRequestRepository apiRequestRepository;
	
	@Value("${spring.mail.username}") 
    private String sender;
    
    @Value("${spring.mail.username}")
	private String username;
	
	@Value("${spring.mail.password}")
	private String password;
	
	@Value("${spring.mail.host}")
	private String host;
	
	@Value("${spring.mail.port}")
	private String port;
	
	@Value("${spring.mail.properties.mail.smtp.auth}")
	private Boolean auth;
	
	@Value("${spring.mail.properties.mail.smtp.starttls.enable}")
	private String enable;
	
	@Value("${app.reg.admin.mob}")
	private String appRegAdminMob;
	
	private static SecretKey secretKey;
    private Cipher encryptionCipher;
    
    private static String appRegAdminOTP="";
    private static String appRegAdminOTPRef="";
    
    static SecureRandom rnd = new SecureRandom();
    
    static
	{
		try
		{
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(APIConstants.KEY_SIZE);
			secretKey = keyGenerator.generateKey();
		}
		catch(Exception e)
		{
			System.out.println("Exception occurred!");
		}
	}
	
	@Override
	public LoginOTPResponseDTO loginGenerateOTP(AbstractRequestDTO requestDTO) throws Exception {
		// TODO Auto-generated method stub
		// Saving the record into api request table
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Login OTP Generation");
		apiRequestEntity.setRequestData(objectToJsonMapper.abstractRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
	    LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		LoginOTPResponseDTO responseDTO=new LoginOTPResponseDTO();
		try
		{
			Optional<LoginEntity> loginEntityOptional=loginRepository.findById(requestDTO.getLoginId());
			LoginEntity loginEntity=loginEntityOptional.get();
			// Hashing the password to verify the user
			String securedPassword= generateSHA256SecuredPassword(requestDTO.getPassword());
			apiRequestEntity.setLoginId(requestDTO.getLoginId());
			// Getting mobile no of user... used to send OTP
			if(loginEntity.getPassword().equals(securedPassword))
			{
				String mobileNo="+91"+loginEntity.getMobNo();
				String tempOTP=""+getRandomNumber(100000,999999);
				String tempRef=""+getRandomNumber(1000,9999);
				loginEntity.setOtp(tempOTP);
				loginEntity.setOtpRequestNo(tempRef);
			    loginEntity.setOtpTimestamp(Timestamp.valueOf(LocalDateTime.now()));
			    loginEntity.setUpdatedOn(new Date());
			    loginEntity.setUpdationType("OTP generation");
			    loginEntity.setLastUpdationTime(ldt);
				Boolean status=sendOTP(tempOTP,tempRef,mobileNo);
				responseDTO.setStatus(status);
				if(status==true)
				{
					loginRepository.save(loginEntity);
					responseDTO.setMsg("OTP sent successfully!");
					responseDTO.setOtpRef(tempRef);
				}
				else
					responseDTO.setMsg("OTP Server is down or busy, Please try after some time!");
			}
			else
			{
				responseDTO.setMsg("Password is not correct!");
				responseDTO.setStatus(false);
			}
		}
		catch(Exception e)
		{
			responseDTO.setMsg("Invalid loginId, Please enter correct loginId!");
			responseDTO.setStatus(false);
		}
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestEntity.setResponseData(objectToJsonMapper.loginOTPResponseToJson(responseDTO));
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}

	@Override
	public LoginResponseDTO loginValidateOTP(LoginRequestDTO requestDTO, String ipAddress)
			throws Exception {
		// Saving the record into api request table
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Login OTP Validation");
		apiRequestEntity.setRequestData(objectToJsonMapper.loginRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		LoginResponseDTO responseDTO=new LoginResponseDTO();
		boolean validationFailed=false;
		try
		{
			Optional<ApplicationEntity> applicationEntityOptional=applicationRepository.findById(requestDTO.getAppId());
			ApplicationEntity applicationEntity=applicationEntityOptional.get();
			if(applicationEntity==null)
			{
				responseDTO.setMsg("Application Id doesn't exist!");
				responseDTO.setStatus(false);
				validationFailed=true;
			}
		}
		catch(Exception e)
		{
			responseDTO.setMsg("Application Id doesn't exist!");
			responseDTO.setStatus(false);
			validationFailed=true;
		}
		
		LoginEntity loginEntity=null;
		if(validationFailed==false)
		{
		try
		{
			Optional<LoginEntity> loginEntityOptional=loginRepository.findById(requestDTO.getLoginId());
			loginEntity=loginEntityOptional.get();
			if(loginEntity==null)
			{
				responseDTO.setMsg("User doesn't exist!");
				responseDTO.setStatus(false);
				validationFailed=true;
			}
		}
		catch(Exception e)
		{
			responseDTO.setMsg("User doesn't exist!");
			responseDTO.setStatus(false);
			validationFailed=true;
		}
		}
		
		if(validationFailed==false)
		{
		UserApplicationEntity userApplicationEntity=userApplicationRepository.findByLoginIdAndAppIdAndEnabled(requestDTO.getLoginId(), requestDTO.getAppId(), true);
		if(userApplicationEntity==null)
		{
			responseDTO.setMsg("User doesn't have access to the application id!");
			responseDTO.setStatus(false);
			validationFailed=true;
		}
		}
		
		if(validationFailed==true)
		{
			apiRequestEntity.setStatus(false);
			apiRequestEntity.setResponseData(objectToJsonMapper.loginResponseToJson(responseDTO));
			apiRequestRepository.save(apiRequestEntity);
			return responseDTO;
		}
		
		AuthenticationLogEntity authenticationLogEntity =new AuthenticationLogEntity();
		try
		{
			apiRequestEntity.setLoginId(requestDTO.getLoginId());
			List<AuthenticationLogEntity> authenticationLogEntities=authenticationLogRepository.findByLoginId(requestDTO.getLoginId());
			apiRequestEntity.setLoginId(requestDTO.getLoginId());
			for(int i=0;i<authenticationLogEntities.size();i++)
			{
				if(authenticationLogEntities.get(i).getLoggedIn()==true)
				{
					responseDTO.setMsg("You're already authenticated, please proceed!");
					responseDTO.setStatus(true);
					apiRequestEntity.setStatus(true);
					apiRequestEntity.setResponseData(objectToJsonMapper.loginResponseToJson(responseDTO));
					apiRequestRepository.save(apiRequestEntity);
					return responseDTO;
				}
			}
			// Hashing the password to verify the user
			String securedPassword=generateSHA256SecuredPassword(requestDTO.getPassword());
			if(!loginEntity.getPassword().equals(securedPassword))
			{
				responseDTO.setMsg("Password is incorrect!");
				responseDTO.setStatus(false);
				authenticationLogEntity.setAuthenticated(false);
				authenticationLogEntity.setStatus(false);
				authenticationLogEntity.setLoggedIn(false);
				authenticationLogEntity.setAuthenticationMsg("Authentication failed");
				authenticationLogEntity.setLoginId(requestDTO.getLoginId());
				authenticationLogEntity.setIpAddress(ipAddress);
				authenticationLogRepository.save(authenticationLogEntity);
				
				apiRequestEntity.setStatus(false);
				apiRequestEntity.setResponseData(objectToJsonMapper.loginResponseToJson(responseDTO));
				apiRequestRepository.save(apiRequestEntity);
				
				return responseDTO;
			}
			if(!loginEntity.getOtp().equals(requestDTO.getOtp()))
			{
				responseDTO.setMsg("OTP is incorrect, please enter request no "+loginEntity.getOtpRequestNo()+" OTP");
				responseDTO.setStatus(false);
				authenticationLogEntity.setAuthenticated(false);
				authenticationLogEntity.setStatus(false);
				authenticationLogEntity.setLoggedIn(false);
				authenticationLogEntity.setAuthenticationMsg("Authentication failed");
				authenticationLogEntity.setLoginId(requestDTO.getLoginId());
				authenticationLogEntity.setIpAddress(ipAddress);
				authenticationLogRepository.save(authenticationLogEntity);
				
				apiRequestEntity.setStatus(false);
				apiRequestEntity.setResponseData(objectToJsonMapper.loginResponseToJson(responseDTO));
				apiRequestRepository.save(apiRequestEntity);
				return responseDTO;
			}
			Long miliSeconds=System.currentTimeMillis()-loginEntity.getOtpTimestamp().getTime();
			Double otpTime= miliSeconds/(1000.0*60.0);
			ConfigEntity configEntity= configRepository.findByUserType("user");
			Double otpExpireTime=configEntity.getOtpExpireTimeInMin()*1.0;
			if(otpTime>otpExpireTime)
			{
				responseDTO.setMsg("OTP is expired, please click to sent again!");
				responseDTO.setStatus(false);
				authenticationLogEntity.setAuthenticated(false);
				authenticationLogEntity.setStatus(false);
				authenticationLogEntity.setLoggedIn(false);
				authenticationLogEntity.setAuthenticationMsg("Authentication failed");
				authenticationLogEntity.setLoginId(requestDTO.getLoginId());
				authenticationLogEntity.setIpAddress(ipAddress);
				authenticationLogRepository.save(authenticationLogEntity);
				
				apiRequestEntity.setStatus(false);
				apiRequestEntity.setResponseData(objectToJsonMapper.loginResponseToJson(responseDTO));
				apiRequestRepository.save(apiRequestEntity);
				return responseDTO;
			}
			ServiceEntity serviceEntity= serviceRepository.findByServiceName(requestDTO.getServiceName());
			if(loginEntity.getEmailVerified()==true && loginEntity.getFirstTimePasswordSet()==true 
				    && loginEntity.getLoginId().equals(requestDTO.getLoginId()) && loginEntity.getPassword().equals(securedPassword))
			{
				//loginEntity.setUpdatedOn(new Date());
			    // Maintaining the record in log table
				authenticationLogEntity.setLoginId(requestDTO.getLoginId());
				authenticationLogEntity.setLoggedInTimestamp(ldt);
				authenticationLogEntity.setIpAddress(ipAddress);
				authenticationLogEntity.setStatus(true);
				authenticationLogEntity.setLoggedIn(true);
				authenticationLogEntity.setAuthenticated(true);
				authenticationLogEntity.setAuthenticationMsg("Authentication succeeded");
				authenticationLogEntity.setAuthenticatedApp(requestDTO.getAppId());
				authenticationLogEntity.setAuthenticatedTimestamp(ldt);
				//loginRepository.save(loginEntity);
				authenticationLogRepository.save(authenticationLogEntity);
				
				responseDTO.setMsg("User is authenticated successfully!");
				responseDTO.setStatus(true);
				
				//LinkedList<Integer> moduleList= (LinkedList<Integer>)loginEntity.getModuleAccess();
				//LinkedList<Integer> moduleList=(LinkedList<Integer>)Arrays.stream(loginEntity.getModuleAccess()).boxed().collect(Collectors.toList());
				int[] serviceLists= loginEntity.getServiceAccess();
 				//LinkedList<Integer> moduleList= (LinkedList<Integer>) Arrays.asList(loginEntity.getModuleAccess());
				if(serviceEntity!=null)
				{
					for(int i=0;i<serviceLists.length;i++)
					{
						if(serviceLists[i]==serviceEntity.getServiceId())
						{
							responseDTO.setAccess(true);
							break;
						}
						else {
							responseDTO.setAccess(false);
						}
					}
				}
				else {
					responseDTO.setStatus(false);
					responseDTO.setMsg("User doesn't have access to this module");
					responseDTO.setAccess(false);
				}
			}
			else
			{
				responseDTO.setMsg("User authentication failed, Please either verify email or set password!");
				responseDTO.setStatus(false);
			}
		}
		catch(Exception e)
		{
			responseDTO.setMsg("Invalid credentials!");
			responseDTO.setStatus(false);
		}
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestEntity.setResponseData(objectToJsonMapper.loginResponseToJson(responseDTO));
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}

	@Override
	public AbstractResponseDTO userLogout(AbstractRequestDTO requestDTO) throws Exception {
		// TODO Auto-generated method stub
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("User Logout");
		apiRequestEntity.setRequestData(objectToJsonMapper.abstractRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		apiRequestEntity.setLoginId(requestDTO.getLoginId());
		
		AbstractResponseDTO responseDTO =new AbstractResponseDTO();
		try
		{
			TokenEntity tokenEntity=tokenRepository.findByLoginId(requestDTO.getLoginId());
			LoginEntity loginEntity=loginRepository.findByLoginId(requestDTO.getLoginId());
			//loginEntity.setUpdatedOn(new Date());
			tokenEntity.setTokenExpired(true);
			
			// updating the loginlog table
			AuthenticationLogEntity authenticationLogEntity=authenticationLogRepository.findByLoginIdAndStatus(requestDTO.getLoginId(), true);
			authenticationLogEntity.setLoggedOutTimestamp(ldt);
			authenticationLogEntity.setStatus(false);
			authenticationLogEntity.setLoggedIn(false);
			authenticationLogRepository.save(authenticationLogEntity);
			//loginRepository.save(loginEntity);
			tokenRepository.save(tokenEntity);
			
			responseDTO.setMsg("Successfully logout!");
			responseDTO.setStatus(true);
		}
		catch(Exception e)
		{
			responseDTO.setMsg("DB server is down, please try after some time!");
			responseDTO.setStatus(false);
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.abstractResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}
	
	@Override
	public ForgetPasswordOTPResponseDTO forgetPasswordGenerateOTP(AbstractRequestDTO requestDTO) throws Exception {
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Forget Password OTP Generation");
		apiRequestEntity.setRequestData(objectToJsonMapper.abstractRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		ForgetPasswordOTPResponseDTO responseDTO=new ForgetPasswordOTPResponseDTO();
		try
		{
			Optional<LoginEntity> loginEntityOptional=loginRepository.findById(requestDTO.getLoginId());
			LoginEntity loginEntity=loginEntityOptional.get();
			// Getting mobile no of user... used to send OTP
			if(loginEntity!=null)
			{
				apiRequestEntity.setLoginId(requestDTO.getLoginId());
				String mobileNo="+91"+loginEntity.getMobNo();
				String tempOTP=""+getRandomNumber(100000,999999);
				String tempRef=""+getRandomNumber(1000,9999);
				loginEntity.setOtp(tempOTP);
				loginEntity.setOtpRequestNo(tempRef);
			    loginEntity.setOtpTimestamp(Timestamp.valueOf(LocalDateTime.now()));
			    loginEntity.setUpdatedOn(new Date());
			    loginEntity.setUpdationType("OTP generation for forget password");
			    loginEntity.setLastUpdationTime(ldt);
				Boolean status=sendOTP(tempOTP,tempRef,mobileNo);
				responseDTO.setStatus(status);
				if(status==true)
				{
					loginRepository.save(loginEntity);
					responseDTO.setMsg("OTP sent successfully!");
					responseDTO.setOtpRef(tempRef);
				}
				else
					responseDTO.setMsg("OTP sent failed!");
			}
			else
			{
				responseDTO.setMsg("Invalid user!");
				responseDTO.setStatus(false);
			}
		}
		catch(Exception e)
		{
			responseDTO.setMsg("Invalid user!");
			responseDTO.setStatus(false);
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.forgetPasswordOTPResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}
	
	@Override
	public ForgetPasswordOTPValidationResponseDTO forgetPasswordOTPValidation(ForgetPasswordOTPRequestDTO requestDTO) throws Exception {
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Forget Password OTP Validation");
		apiRequestEntity.setRequestData(objectToJsonMapper.abstractRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		ForgetPasswordOTPValidationResponseDTO responseDTO=new ForgetPasswordOTPValidationResponseDTO();
		try
		{
			Optional<LoginEntity> loginEntityOptional=loginRepository.findById(requestDTO.getLoginId());
			LoginEntity loginEntity=loginEntityOptional.get();
			apiRequestEntity.setLoginId(requestDTO.getLoginId());
			if(loginEntity.getOtp().equals(requestDTO.getOtp()))
			{
				responseDTO.setMsg("OTP is validated & passcode is generated!");
				responseDTO.setStatus(true);
				// generating user identity code to set password
				String passwordCode=getRandomStringForVerificationCode(257);
				// encrypting the code
				String encPasswordCode=encrypt(passwordCode);
				// handling the cases of / , + & =
				encPasswordCode=replaceBase64Char(encPasswordCode);
				loginEntity.setUpdatedOn(new Date());
				loginEntity.setPasswordCode(passwordCode);
				loginEntity.setUpdationType("Password code generation");
			    loginEntity.setLastUpdationTime(ldt);
				loginRepository.save(loginEntity);
				responseDTO.setStatus(true);
				responseDTO.setKey(encPasswordCode);
			}
			else
			{
				responseDTO.setMsg("OTP is incorrect, please enter request no "+loginEntity.getOtpRequestNo()+" OTP");
				responseDTO.setStatus(false);
			}
		}
		catch(Exception e)
		{
			responseDTO.setMsg("Invalid user!");
			responseDTO.setStatus(false);
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.forgetPasswordOTPValidationResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}
	
	@Override
	public AbstractResponseDTO setPassword(SetPasswordRequestDTO requestDTO) throws Exception {
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Set Password");
		apiRequestEntity.setRequestData(objectToJsonMapper.setPasswordRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		AbstractResponseDTO responseDTO=new AbstractResponseDTO();
		String key=replaceAddedChar(requestDTO.getKey());
		
		try
		{
			// Decrypting password code
			key= decrypt(key);
			LoginEntity loginEntity=loginRepository.findByPasswordCode(key);
			if(loginEntity!=null)
			{
				// Hashing the password using SHA-256
				apiRequestEntity.setLoginId(loginEntity.getLoginId());
				String securedPassword=generateSHA256SecuredPassword(requestDTO.getPassword());
				if(loginEntity.getFirstTimePasswordSet()==false)
				{
					loginEntity.setFirstTimePasswordSet(true);
					loginEntity.setLastThreePasswords(securedPassword);
				}
				else if(loginEntity.getFirstTimePasswordSet()==true)
				{
					String[] arrayOfLastPasswords = loginEntity.getLastThreePasswords().split(",");
					if(arrayOfLastPasswords.length==1 && !arrayOfLastPasswords[0].equals(securedPassword))
					{
						loginEntity.setLastThreePasswords(loginEntity.getLastThreePasswords()+","+securedPassword);
					}
					else if(arrayOfLastPasswords.length==2 && !arrayOfLastPasswords[0].equals(securedPassword) && !arrayOfLastPasswords[1].equals(securedPassword))
					{
						loginEntity.setLastThreePasswords(loginEntity.getLastThreePasswords()+","+securedPassword);
					}
					else if(arrayOfLastPasswords.length==3 && !arrayOfLastPasswords[0].equals(securedPassword) && !arrayOfLastPasswords[1].equals(securedPassword) && !arrayOfLastPasswords[2].equals(securedPassword))
					{
						loginEntity.setLastThreePasswords(arrayOfLastPasswords[1]+","+arrayOfLastPasswords[2]+","+securedPassword);
					}
					else
					{
						responseDTO.setMsg("Password shouldn't be last three passwords!");
						responseDTO.setStatus(false);
						apiRequestEntity.setResponseData(objectToJsonMapper.abstractResponseToJson(responseDTO));
						apiRequestEntity.setStatus(responseDTO.getStatus());
						apiRequestRepository.save(apiRequestEntity);
						return responseDTO;
					}
				}
				loginEntity.setUpdatedOn(new Date());
				loginEntity.setPassword(securedPassword);
				loginEntity.setLastPasswordChangeTime(ldt);
				loginEntity.setUpdationType("Password change");
			    loginEntity.setLastUpdationTime(ldt);
				loginRepository.save(loginEntity);
				responseDTO.setMsg("Password set successfully!");
				responseDTO.setStatus(true);
			}
			else
			{
				responseDTO.setMsg("Key is either invalid or expired!");
				responseDTO.setStatus(false);
			}
		}
		catch(Exception e)
		{
			responseDTO.setMsg("Key is either invalid or expired!");
			responseDTO.setStatus(false);
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.abstractResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}
	
	@Override
	public ChangePasswordOTPResponseDTO currentPasswordValidation(AbstractRequestDTO requestDTO) throws Exception {
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Current Password Validation");
		apiRequestEntity.setRequestData(objectToJsonMapper.abstractRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		ChangePasswordOTPResponseDTO responseDTO=new ChangePasswordOTPResponseDTO();
		try
		{
			Optional<LoginEntity> loginEntityOptional=loginRepository.findById(requestDTO.getLoginId());
			LoginEntity loginEntity=loginEntityOptional.get();
			apiRequestEntity.setLoginId(requestDTO.getLoginId());
			// Hashing the password to verify the user
			String securedPassword=generateSHA256SecuredPassword(requestDTO.getPassword());
			// Getting mobile no of user... used to send OTP
			if(loginEntity!=null && loginEntity.getPassword().equals(securedPassword))
			{
				String mobileNo="+91"+loginEntity.getMobNo();
				String tempOTP=""+getRandomNumber(100000,999999);
				String tempRef=""+getRandomNumber(1000,9999);
				loginEntity.setOtp(tempOTP);
				loginEntity.setOtpRequestNo(tempRef);
			    loginEntity.setOtpTimestamp(Timestamp.valueOf(LocalDateTime.now()));
			    loginEntity.setUpdatedOn(new Date());
			    loginEntity.setUpdationType("OTP generation for change password");
			    loginEntity.setLastUpdationTime(ldt);
				Boolean status=sendOTP(tempOTP,tempRef,mobileNo);
				responseDTO.setStatus(status);
				if(status==true)
				{
					loginRepository.save(loginEntity);
					responseDTO.setMsg("OTP sent successfully!");
					responseDTO.setOtpRef(tempRef);
				}
				else
					responseDTO.setMsg("OTP sent failed!");
			}
			else
			{
				responseDTO.setMsg("Invalid credentials!");
				responseDTO.setStatus(false);
			}
		}
		catch(Exception e)
		{
			responseDTO.setMsg("Invalid credentials!");
			responseDTO.setStatus(false);
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.changePasswordOTPResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}
	
	@Override
	public ChangePasswordOTPValidationResponseDTO changePasswordOTPValidation(ChangePasswordOTPRequestDTO requestDTO)
			throws Exception {
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Change Password OTP Validation");
		apiRequestEntity.setRequestData(objectToJsonMapper.abstractRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		ChangePasswordOTPValidationResponseDTO responseDTO=new ChangePasswordOTPValidationResponseDTO();
		try
		{
			Optional<LoginEntity> loginEntityOptional=loginRepository.findById(requestDTO.getLoginId());
			LoginEntity loginEntity=loginEntityOptional.get();
			apiRequestEntity.setLoginId(requestDTO.getLoginId());
			if(loginEntity.getOtp().equals(requestDTO.getOtp()))
			{
				responseDTO.setMsg("OTP Validated!");
				responseDTO.setStatus(true);
				// generating user identity code to set password
				String passwordCode=getRandomStringForVerificationCode(257);
				// encrypting the code
				String encPasswordCode=encrypt(passwordCode);
				// handling the cases of / , + & =
				encPasswordCode=replaceBase64Char(encPasswordCode);
				loginEntity.setUpdatedOn(new Date());
				loginEntity.setPasswordCode(passwordCode);
				loginEntity.setUpdationType("Password code generation");
			    loginEntity.setLastUpdationTime(ldt);
				loginRepository.save(loginEntity);
				responseDTO.setStatus(true);
				responseDTO.setKey(encPasswordCode);
			}
			else
			{
				responseDTO.setMsg("OTP is not correct!");
				responseDTO.setStatus(false);
			}
		}
		catch(Exception e)
		{
			responseDTO.setMsg("Invalid user!");
			responseDTO.setStatus(false);
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.changePasswordOTPValidationResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}
	
	@Override
	public AbstractResponseDTO addAppToUser(AddRemoveApplRequestDTO requestDTO) throws Exception {
		// TODO Auto-generated method stub
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Add appl to user");
		apiRequestEntity.setRequestData(objectToJsonMapper.addApplRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		AbstractResponseDTO responseDTO=new AbstractResponseDTO();
		try
		{
			Optional<LoginEntity> loginEntityOptional=loginRepository.findById(requestDTO.getLoginId());
			LoginEntity loginEntity=loginEntityOptional.get();
			apiRequestEntity.setLoginId("Admin login id");
			if(loginEntity!=null)
			{
				UserApplicationEntity userApplicationEntity= userApplicationRepository.findByLoginIdAndAppIdAndEnabled(requestDTO.getLoginId(), requestDTO.getAppId(), true);
				if(userApplicationEntity!=null)
				{
					responseDTO.setMsg("Application is already assigned to user!");
					responseDTO.setStatus(false);
				}
				else
				{
					UserApplicationEntity userApplicationEntityAdd=new UserApplicationEntity();
					userApplicationEntityAdd.setAppId(requestDTO.getAppId());
					userApplicationEntityAdd.setLoginId(requestDTO.getLoginId());
					userApplicationEntityAdd.setCreatedOn(new Date());
					userApplicationEntityAdd.setUpdatedOn(new Date());
					userApplicationEntityAdd.setEnabled(true);
					userApplicationRepository.save(userApplicationEntityAdd);
					responseDTO.setMsg("Application is added to user!");
					responseDTO.setStatus(true);
				}
			}
			else
			{
				responseDTO.setMsg("User doesn't exist!");
				responseDTO.setStatus(false);
			}
		}
		catch(Exception e)
		{
			responseDTO.setMsg("User doesn't exist");
			responseDTO.setStatus(false);
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.abstractResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}
	
	@Override
	public AbstractResponseDTO removeAppToUser(AddRemoveApplRequestDTO requestDTO) throws Exception {
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Remove appl from user");
		apiRequestEntity.setRequestData(objectToJsonMapper.addApplRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		AbstractResponseDTO responseDTO=new AbstractResponseDTO();
		try
		{
			Optional<LoginEntity> loginEntityOptional=loginRepository.findById(requestDTO.getLoginId());
			LoginEntity loginEntity=loginEntityOptional.get();
			apiRequestEntity.setLoginId("Admin login id");
			if(loginEntity!=null)
			{
				UserApplicationEntity userApplicationEntity= userApplicationRepository.findByLoginIdAndAppIdAndEnabled(requestDTO.getLoginId(), requestDTO.getAppId(), true);
				if(userApplicationEntity==null)
				{
					responseDTO.setMsg("Application is not assigned to user!");
					responseDTO.setStatus(false);
				}
				else
				{
					userApplicationEntity.setUpdatedOn(new Date());
					userApplicationEntity.setEnabled(false);
					userApplicationRepository.save(userApplicationEntity);
					responseDTO.setMsg("Application is removed from user access!");
					responseDTO.setStatus(true);
				}
			}
			else
			{
				responseDTO.setMsg("User doesn't exist!");
				responseDTO.setStatus(false);
			}
		}
		catch(Exception e)
		{
			responseDTO.setMsg("User doesn't exist");
			responseDTO.setStatus(false);
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.abstractResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}
	
	@Override
	public SendOTPResponseDTO sendOTP(SendOTPRequestDTO requestDTO) throws Exception {
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Send OTP");
		apiRequestEntity.setRequestData(objectToJsonMapper.sendOTPRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		SendOTPResponseDTO responseDTO=new SendOTPResponseDTO();
		try
		{
			// Generate OTP
			String tempOTP=""+getRandomNumber(100000,999999);
			String tempRef="Ref"+getRandomNumber(1000,9999);
			Boolean status=sendOTP(tempOTP, tempRef,"+91"+requestDTO.getMobNo());
			if(status==true)
			{
				ApplicationEntity applicationEntity =new ApplicationEntity();
				applicationEntity.setAppName(requestDTO.getAppName());
				applicationEntity.setAppShortCode(requestDTO.getAppShortCode());
				applicationEntity.setAdminEmail(requestDTO.getEmailId());
				applicationEntity.setAdminMob(requestDTO.getMobNo());
				applicationEntity.setEnabled(false);
				applicationEntity.setMobVerified(false);
				applicationEntity.setEmailVerified(false);
				applicationEntity.setOtp(tempOTP);
				applicationEntity=applicationRepository.save(applicationEntity);
				responseDTO.setAppId(applicationEntity.getAppId());
				responseDTO.setMsg("OTP Sent successfully!");
				responseDTO.setStatus(true);
			}
			else
			{
				responseDTO.setMsg("OTP Server is down or busy, please try after some time!");
				responseDTO.setStatus(false);
			}
		}
		catch(Exception e)
		{
			responseDTO.setMsg("OTP sending failed!");
			responseDTO.setStatus(false);
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.sendOTPResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}
	
	@Override
	public LoginOTPResponseDTO createApplication(ApplicationCreationRequestDTO requestDTO) throws Exception {
		// TODO Auto-generated method stub
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Create application");
		apiRequestEntity.setRequestData(objectToJsonMapper.applicationCreationRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		LoginOTPResponseDTO responseDTO=new LoginOTPResponseDTO();
		try
		{
			// Generate OTP
			String tempOTP=""+getRandomNumber(100000,999999);
			String tempRef=""+getRandomNumber(1000,9999);
			Boolean status=sendOTP(tempOTP, tempRef,"+91"+appRegAdminMob);
			if(status==true)
			{
				appRegAdminOTP=tempOTP;
				appRegAdminOTPRef=tempRef;
				responseDTO.setMsg("OTP Sent successfully!");
				responseDTO.setStatus(true);
				responseDTO.setOtpRef(tempRef);
			}
			else
			{
				responseDTO.setMsg("OTP sending failed!");
				responseDTO.setStatus(false);
			}
		}
		catch(Exception e)
		{
			responseDTO.setStatus(false);
			responseDTO.setMsg("OTP sending failed!");
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.loginOTPResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}
	
	@Override
	public AbstractResponseDTO verifyAdminOTPAndCreateApplication(VerifyAdminOTPRequestDTO requestDTO)
			throws Exception {
		// TODO Auto-generated method stub
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Verify Admin OTP");
		apiRequestEntity.setRequestData(objectToJsonMapper.verifyAdminOTPRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		AbstractResponseDTO responseDTO=new AbstractResponseDTO();
		try
		{
			if(appRegAdminOTP.equals(requestDTO.getAdminOtp()))
			{
				ApplicationEntity applicationEntity =new ApplicationEntity();
				applicationEntity.setAppName(requestDTO.getAppName());
				applicationEntity.setAppShortCode(requestDTO.getAppShortCode());
				applicationEntity.setAdminEmail(requestDTO.getEmailId());
				applicationEntity.setAdminMob(requestDTO.getMobNo());
				applicationEntity.setEnabled(false);
				applicationEntity.setMobVerified(false);
				applicationEntity.setEmailVerified(false);
				applicationEntity.setKey(getRandomStringForVerificationCode(257));
				
				Boolean status=sendMail(requestDTO.getEmailId(),applicationEntity.getKey(),requestDTO.getAppName());
				
				if(status==true)
				{
					applicationRepository.save(applicationEntity);
					responseDTO.setMsg("App created & verification link sent to email!");
					responseDTO.setStatus(true);
				}
				else
				{
					responseDTO.setMsg("Email Server is down or busy, please try after some time!");
					responseDTO.setStatus(false);
				}
				
			}
			else
			{
				responseDTO.setMsg("OTP is invalid, please enter correct OTP!");
				responseDTO.setStatus(false);
			}
		}
		catch(Exception e)
		{
			responseDTO.setMsg("App creation failed!");
			responseDTO.setStatus(false);
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.abstractResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}
	
	
	public Boolean sendMail(String email, String verificationCode, String appName) throws Exception {
		Properties prop = new Properties();
		prop.put("mail.smtp.auth", auth);
		prop.put("mail.smtp.starttls.enable", enable);
		prop.put("mail.smtp.host", host);
		prop.put("mail.smtp.port", port);
		
		Session session = Session.getInstance(prop, new Authenticator() {
		    @Override
		    protected PasswordAuthentication getPasswordAuthentication() {
		        return new PasswordAuthentication(username, password);
		    }
		});
		Message message = new MimeMessage(session);
		try
		{
			message.setFrom(new InternetAddress(username,false));
			message.setRecipients(
					Message.RecipientType.TO, InternetAddress.parse(email));
			message.setSubject("Verification process for subscription of login services");
			
			// Encrypting verification code
			verificationCode=encrypt(verificationCode);
			verificationCode=replaceBase64Char(verificationCode);
			
			String htmlContent="<div><span class='il'>Dear </span><span class='il'>Sir</span>/<span class='il'>Madam</span>,";
			htmlContent+="<p>We are happy to see your interest for subscribing the login services for the application, namely <b>"+appName+"</b>.</p>";
			htmlContent+="<p>This is the verification email for verifying your email & mobile no.</p>";
			htmlContent+="<p>1. Kindly click below to verify your email:<p>";
			htmlContent+="<a href="+"http://localhost:4200/email/verification?key="+verificationCode+ " style='word-break: break-all;'"+" target='_blank'>"+"http://localhost:4200/email/verification?key="+verificationCode+"</a>";
			htmlContent+="<p>2. On clicking the link you will receive an OTP and redirected to new page for mobile no verification.</p>";
			htmlContent+="<p>3. We will intimate to you about your key and Applicaion Id on successful verification of email and mobile no in next email.</p><br>";
			htmlContent+="<p>This is a System Generated Email, Please Don't Reply.</p>";
			htmlContent+="<p>Thank you,<p>";
			htmlContent+="<p>CBN Team</p>";
			//String htmlContent="<a href="+"http://localhost:4200/email/verification?key="+verificationCode+ " target='_blank'>"+"http://localhost:4200/email/verification?key="+verificationCode+"</a>";
			MimeBodyPart messageBodyPart = new MimeBodyPart(); 
			messageBodyPart.setContent(htmlContent, "text/html");

			Multipart multipart = new MimeMultipart();
			multipart.addBodyPart(messageBodyPart);
			message.setContent(multipart);
			Transport.send(message);
			return true;
		}
		catch(Exception e)
		{
			return false;
		}
	}
	
	@Override
	public AbstractResponseDTO createUser(UserCreationRequestDTO requestDTO) throws Exception {
		// TODO Auto-generated method stub
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Create user");
		apiRequestEntity.setRequestData(objectToJsonMapper.userCreationRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		AbstractResponseDTO responseDTO=new AbstractResponseDTO();
		try
		{
			// check application Id
			ApplicationEntity applicationEntity = applicationRepository.findByAppId(requestDTO.getAppId());
			String securedPassword=generateSHA256SecuredPassword(requestDTO.getPassword());
			if(applicationEntity!=null)
			{
				LoginEntity loginEntity=new LoginEntity();
				loginEntity.setLoginId(requestDTO.getEmail());
				loginEntity.setUserId(requestDTO.getEmail());
				loginEntity.setEmailVerified(true);
				loginEntity.setMobileVerified(true);
				loginEntity.setFirstTimePasswordSet(true);
				loginEntity.setPassword(securedPassword);
				loginEntity.setMobNo(requestDTO.getMobNo());
				loginEntity.setEnabled(true);
				loginEntity.setCreatedOn(new Date());
				loginEntity.setLastThreePasswords(securedPassword);
				
				// Getting the appl Id
				UserApplicationEntity userApplicationEntity=new UserApplicationEntity();
				userApplicationEntity.setAppId(applicationEntity.getAppId());
				userApplicationEntity.setLoginId(requestDTO.getEmail());
				userApplicationEntity.setCreatedOn(new Date());
				userApplicationEntity.setEnabled(true);
				userApplicationEntity.setMobNo(requestDTO.getMobNo());
				userApplicationEntity.setEmail(requestDTO.getEmail());
				
				loginRepository.save(loginEntity);
				userApplicationRepository.save(userApplicationEntity);
				
				responseDTO.setStatus(true);
				responseDTO.setMsg("User is created!");
			}
			else
			{
				responseDTO.setMsg("Application doesn't exist!");
				responseDTO.setStatus(false);
			}
		}
		catch(Exception e)
		{
			responseDTO.setMsg("User creation failed");
			responseDTO.setStatus(false);
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.abstractResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}
	
	@Override
	public LoginOTPResponseDTO emailVerification(String key) throws Exception {
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Email Verification");
		String requestData="{ key: "+key+" }";
		apiRequestEntity.setRequestData(requestData);
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		LoginOTPResponseDTO responseDTO=new LoginOTPResponseDTO();
		key=replaceAddedChar(key);
		try
		{
			// Decrypting verification code
			key= decrypt(key);
			
			ApplicationEntity applicationEntity=applicationRepository.findByKey(key);
			if(applicationEntity!=null)
			{
				if(applicationEntity.getEmailVerified()==false)
				{
					applicationEntity.setEmailVerified(true);
					applicationEntity.setCreatedOn(new Date());
					
					// Generate OTP
					String tempOTP=""+getRandomNumber(100000,999999);
					String tempRef=""+getRandomNumber(1000,9999);
					applicationEntity.setOtp(tempOTP);
					Boolean status=sendOTPToAppAdmin(tempOTP, tempRef,"+91"+applicationEntity.getAdminMob());
					if(status==true)
					{
						applicationRepository.save(applicationEntity);
						responseDTO.setOtpRef(tempRef);
						responseDTO.setAppId(applicationEntity.getAppId());
						responseDTO.setStatus(true);
						responseDTO.setMsg("Email verified & OTP sent to Mob!");
					}
					else
					{
						responseDTO.setStatus(false);
						responseDTO.setMsg("Email verified, but OTP server is down or busy!");
					}
					
				}
				else
				{
					responseDTO.setMsg("Email is already verified & OTP has been sent!");
					responseDTO.setStatus(false);
				}
			}
			else
			{
				responseDTO.setMsg("Verification link is either expired or invalid!");
				responseDTO.setStatus(false);
			}
		}
		catch(Exception e)
		{
			responseDTO.setMsg("Email not verified!");
			responseDTO.setStatus(false);
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.loginOTPResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}
	
	@Override
	public AbstractResponseDTO mobileVerification(MobileVerificationRequestDTO requestDTO) throws Exception {
		// TODO Auto-generated method stub
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Mobile Verification");
		apiRequestEntity.setRequestData(objectToJsonMapper.mobileVerificationRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		AbstractResponseDTO responseDTO=new AbstractResponseDTO();
		try
		{
			ApplicationEntity applicationEntity=applicationRepository.findByAppId(requestDTO.getAppId());
			if(applicationEntity!=null && applicationEntity.getOtp().equals(requestDTO.getOtp()))
			{
				applicationEntity.setUpdatedOn(new Date());
				applicationEntity.setEnabled(true);
				applicationEntity.setMobVerified(true);
				applicationEntity.setKey(getRandomStringForVerificationCode(257));
				
				// Send details related email
				
				Boolean status=sendAppDetailsMail(applicationEntity.getAdminEmail(),applicationEntity.getAppId(),applicationEntity.getAppName(),applicationEntity.getAppShortCode(),applicationEntity.getKey());
				if(status==true)
				{
					applicationRepository.save(applicationEntity);
					responseDTO.setMsg("Mobile verified & application details sent to email!");
					responseDTO.setStatus(true);
				}
				else
				{
					applicationRepository.save(applicationEntity);
					responseDTO.setMsg("Mobile verified, but application details couldn't be sent since Email server is either down or busy!");
					responseDTO.setStatus(false);
				}
			}
			else if(applicationEntity!=null && !applicationEntity.getOtp().equals(requestDTO.getOtp()))
			{
				responseDTO.setMsg("OTP is incorrect, plese enter request no OTP!");
				responseDTO.setStatus(false);
			}
			else
			{
				responseDTO.setMsg("Invalid AppId!");
				responseDTO.setStatus(false);
			}
		}
		catch(Exception e)
		{
			responseDTO.setMsg("Invalid AppId!");
			responseDTO.setStatus(false);
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.abstractResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}
	
	@Override
	public UserInfoResponseDTO getUserInfo(String key) throws Exception {
		// TODO Auto-generated method stub
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Get User Info");
		String requestData="{ key: "+key+" }";
		apiRequestEntity.setRequestData(requestData);
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		UserInfoResponseDTO responseDTO=new UserInfoResponseDTO();
		key=replaceAddedChar(key);
		try
		{
			// Decrypting verification code
			key= decrypt(key);
						
			ApplicationEntity applicationEntity=applicationRepository.findByKey(key);
			if(applicationEntity!=null)
			{
				applicationEntity.setKey(getRandomStringForVerificationCode(257));
				applicationEntity.setUpdatedOn(new Date());
				// encrypting the key
				key=encrypt(applicationEntity.getKey());
				key=replaceBase64Char(key);
				responseDTO.setAppId(applicationEntity.getAppId());
				responseDTO.setAppShortCode(applicationEntity.getAppShortCode());
				responseDTO.setUserId(applicationEntity.getAdminEmail());
				applicationRepository.save(applicationEntity);
				responseDTO.setKey(key);
				responseDTO.setStatus(true);
			}
			else
			{
				responseDTO.setStatus(false);
				responseDTO.setMsg("Couldn't verify the link, Link must be broken!");
			}
		}
		catch(Exception e)
		{
			responseDTO.setStatus(false);
			responseDTO.setMsg("Couldn't verify the link, Link must be broken!");
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.abstractResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}
	
	@Override
	public AuthenticatedUserListResponseDTO authenticatedUserList(AuthenticatedUserListRequestDTO requestDTO)
			throws Exception {
		// TODO Auto-generated method stub
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Get Authenticated User List");
		apiRequestEntity.setRequestData(objectToJsonMapper.authenticatedUserListRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		AuthenticatedUserListResponseDTO responseDTO=new AuthenticatedUserListResponseDTO();
		List<AuthenticatedUser> authenticatedUserList= new LinkedList<AuthenticatedUser>();
		List<AuthenticatedUser> authenticatedTopUserList= new LinkedList<AuthenticatedUser>();
		List<AuthenticatedUser> authenticatedTopUserListTemp= new LinkedList<AuthenticatedUser>();
		List<AuthenticatedUser> authenticatedBottomUserList= new LinkedList<AuthenticatedUser>();
		List<AuthenticatedUser> authenticatedBottomUserListTemp= new LinkedList<AuthenticatedUser>();
		List<AuthenticatedUser> unAuthenticatedUserList= new LinkedList<AuthenticatedUser>();
		try
		{
		    //LocalDateTime date = LocalDateTime.now();
		    //LocalDateTime newDate = date.minusDays(requestDTO.getNoOfDays());
		    
		    // code to convert date into specified format
		    //DateTimeFormatter format_date_of_today = DateTimeFormatter.ofPattern("yyyy-MM-dd");
		    //String formattedDate = date.format(format_date_of_today);
		    //String formattedNewDate = newDate.format(format_date_of_today);
		    
		    String firstDate=requestDTO.getFirstDate()+"T00:00:00.000";
		    String lastDate=requestDTO.getLastDate()+"T23:59:59.999";
			LocalDateTime date1 = LocalDateTime.parse(firstDate);
			LocalDateTime date2 = LocalDateTime.parse(lastDate);
		    
		    List<AuthenticationLogEntity> unfilteredAuthenticatedUserLists=authenticationLogRepository.findAllAuthenticatedUsers(date1,date2, requestDTO.getAppId());
		    int serialNo=1;
		    for(AuthenticationLogEntity authenticationLogEntity: unfilteredAuthenticatedUserLists)
			{
		    	AuthenticatedUser authenticatedUser=new AuthenticatedUser();
		    	authenticatedUser.setSerialNo(serialNo);
				authenticatedUser.setLoginId(authenticationLogEntity.getLoginId());
				authenticatedUser.setAccessedDate(Date.from(authenticationLogEntity.getAuthenticatedTimestamp().toInstant(ZoneOffset.UTC)));
				authenticatedUser.setLoginTime(authenticationLogEntity.getAuthenticatedTimestamp().toString());
				authenticatedUserList.add(authenticatedUser);
				serialNo++;
			}
		    // Extracting unique users
		 	Set<String> uniqueUsers = new HashSet<String>();
		 	for(AuthenticationLogEntity authenticationLogEntity: unfilteredAuthenticatedUserLists) {
		 		uniqueUsers.add(authenticationLogEntity.getLoginId());
		 	}
		 	
		 	serialNo=1;
		 	for (String loginId : uniqueUsers)
		    {
		    	AuthenticatedUser authenticatedUser=new AuthenticatedUser();
		    	long count=0;
		    	for(AuthenticationLogEntity authenticationLogEntity: unfilteredAuthenticatedUserLists)
		    	{
		    		if(authenticationLogEntity.getLoginId().equals(loginId))
		    			count++;
		    	}
		    	authenticatedUser.setSerialNo(serialNo);
		    	authenticatedUser.setLoginId(loginId);
		    	authenticatedUser.setFrequency(count);
		    	authenticatedTopUserList.add(authenticatedUser);
		    	serialNo++;
		    }
		    authenticatedTopUserList.sort(Comparator.comparing(AuthenticatedUser::getFrequency, Comparator.reverseOrder()));
	    	for(int i=0;i<authenticatedTopUserList.size() && i<5;i++)
	    	{
	    		authenticatedTopUserListTemp.add(authenticatedTopUserList.get(i));
	    	}
	    	
	    	// for bottom users
	    	serialNo=1;
	    	for (String loginId : uniqueUsers)
		    {
	    		AuthenticatedUser authenticatedUser=new AuthenticatedUser();
		    	long count=0;
		    	for(AuthenticationLogEntity authenticationLogEntity: unfilteredAuthenticatedUserLists)
		    	{
		    		if(authenticationLogEntity.getLoginId().equals(loginId))
		    			count++;
		    	}
		    	authenticatedUser.setSerialNo(serialNo);
		    	authenticatedUser.setLoginId(loginId);
		    	authenticatedUser.setFrequency(count);
		    	authenticatedBottomUserList.add(authenticatedUser);
		    	serialNo++;
		    }
	    	authenticatedBottomUserList.sort(Comparator.comparing(AuthenticatedUser::getFrequency));
	    	for(int i=0;i<authenticatedBottomUserList.size() && i<5;i++)
	    	{
	    		authenticatedBottomUserListTemp.add(authenticatedBottomUserList.get(i));
	    	}
	    	
	    	List<String> unfilteredUnAuthenticatedUserLists=authenticationLogRepository.findAllUnAuthenticatedUsers(date1,date2, requestDTO.getAppId());
	    	serialNo=1;
	    	for(String s: unfilteredUnAuthenticatedUserLists)
	    	{
	    		AuthenticatedUser authenticatedUser=new AuthenticatedUser();
	    		authenticatedUser.setSerialNo(serialNo);
	    		authenticatedUser.setLoginId(s);
	    		LoginEntity loginEntity=loginRepository.findByLoginId(s);
	    		authenticatedUser.setMobNo(loginEntity.getMobNo());
	    		unAuthenticatedUserList.add(authenticatedUser);
	    		serialNo++;
	    	}
	    	
	    	responseDTO.setUnAuthenticatedUserList(unAuthenticatedUserList);
	    	responseDTO.setAuthenticatedBottomUserList(authenticatedBottomUserListTemp);
	    	responseDTO.setAuthenticatedTopUserList(authenticatedTopUserListTemp);
		    responseDTO.setAuthenticatedUserList(authenticatedUserList);
		    responseDTO.setMsg("Fetched user list successfully!");
		    responseDTO.setStatus(true);
		}
		catch(Exception e)
		{
			responseDTO.setMsg("User list couldn't be retrived, either because of application id doesn't exist or db server is down!");
		    responseDTO.setStatus(false);
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.authenticatedUserListResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}
	
	
	@Override
	public AuthenticatedUserListResponseDTO authenticatedUserListOnDay(AuthenticatedUserListRequestDTO requestDTO)
			throws Exception {
		// TODO Auto-generated method stub
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Get Authenticated User List On Day");
		apiRequestEntity.setRequestData(objectToJsonMapper.authenticatedUserListRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		AuthenticatedUserListResponseDTO responseDTO=new AuthenticatedUserListResponseDTO();
		List<AuthenticatedUser> authenticatedUserList= new LinkedList<AuthenticatedUser>();
		List<AuthenticatedUser> authenticatedTopUserList= new LinkedList<AuthenticatedUser>();
		List<AuthenticatedUser> authenticatedBottomUserList= new LinkedList<AuthenticatedUser>();
		try
		{
			// Creating the string for date
			String date=requestDTO.getYear()+"-";
			if(requestDTO.getMonth().length()==1)
				date+="0"+requestDTO.getMonth()+"-";
			else
				date+=requestDTO.getMonth()+"-";
			
			if(requestDTO.getDay().length()==1)
				date+="0"+requestDTO.getDay();
			else
				date+=requestDTO.getDay();
			
			String date1=date+"T00:00:00.000";
			String date2=date+"T23:59:59.999";
			LocalDateTime dateTime1 = LocalDateTime.parse(date1);
			LocalDateTime dateTime2 = LocalDateTime.parse(date2);
		    List<AuthenticationLogEntity> unfilteredAuthenticatedUserLists=authenticationLogRepository.findAllAuthenticatedUsersOnDay(dateTime1, dateTime2, requestDTO.getAppId());
		    // Extracting unique users
		 	Set<String> uniqueUsers = new HashSet<String>();
		 	for(AuthenticationLogEntity authenticationLogEntity: unfilteredAuthenticatedUserLists) {
		 		uniqueUsers.add(authenticationLogEntity.getLoginId());
		 	}
		 	
		 	if(requestDTO.getTopwise()!=null && requestDTO.getTopwise()==true)
		    {
		    	// for top users
		 		for (String loginId : uniqueUsers)
			    {
			    	AuthenticatedUser authenticatedUser=new AuthenticatedUser();
			    	long count=0;
			    	for(AuthenticationLogEntity authenticationLogEntity: unfilteredAuthenticatedUserLists)
			    	{
			    		if(authenticationLogEntity.getLoginId().equals(loginId))
			    			count++;
			    	}
			    	authenticatedUser.setLoginId(loginId);
			    	authenticatedUser.setFrequency(count);
			    	authenticatedTopUserList.add(authenticatedUser);
			    }
			    authenticatedTopUserList.sort(Comparator.comparing(AuthenticatedUser::getFrequency, Comparator.reverseOrder()));
		    	for(int i=0;i<authenticatedTopUserList.size() && i<requestDTO.getTopNo();i++)
		    	{
		    		authenticatedUserList.add(authenticatedTopUserList.get(i));
		    	}
		    }
		    else if(requestDTO.getBottomwise()!=null && requestDTO.getBottomwise()==true)
		    {
		    	// for bottom users
		    	for (String loginId : uniqueUsers)
			    {
		    		AuthenticatedUser authenticatedUser=new AuthenticatedUser();
			    	long count=0;
			    	for(AuthenticationLogEntity authenticationLogEntity: unfilteredAuthenticatedUserLists)
			    	{
			    		if(authenticationLogEntity.getLoginId().equals(loginId))
			    			count++;
			    	}
			    	authenticatedUser.setLoginId(loginId);
			    	authenticatedUser.setFrequency(count);
			    	authenticatedBottomUserList.add(authenticatedUser);
			    }
		    	authenticatedBottomUserList.sort(Comparator.comparing(AuthenticatedUser::getFrequency));
		    	for(int i=0;i<authenticatedBottomUserList.size() && i<requestDTO.getBottomNo();i++)
		    	{
		    		authenticatedUserList.add(authenticatedBottomUserList.get(i));
		    	}
		    }
		    else
		    {
		    	// for showing all users list
		    	for(AuthenticationLogEntity authenticationLogEntity: unfilteredAuthenticatedUserLists)
			    {
			    	AuthenticatedUser authenticatedUser=new AuthenticatedUser();
			    	authenticatedUser.setLoginId(authenticationLogEntity.getLoginId());
			    	authenticatedUser.setAccessedDate(Date.from(authenticationLogEntity.getAuthenticatedTimestamp().toInstant(ZoneOffset.UTC)));
			    	authenticatedUserList.add(authenticatedUser);
			    }
		    }
		 	
		    responseDTO.setAuthenticatedUserList(authenticatedUserList);
		    responseDTO.setMsg("Fetched user list successfully!");
		    responseDTO.setStatus(true);
		}
		catch(Exception e)
		{
			responseDTO.setMsg("user list fetching unsuccessful!");
		    responseDTO.setStatus(false);
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.authenticatedUserListResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}

	@Override
	public AuthenticatedUserListResponseDTO authenticatedUserListOnMonth(AuthenticatedUserListRequestDTO requestDTO)
			throws Exception {
		// TODO Auto-generated method stub
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Get Authenticated User List On Month");
		apiRequestEntity.setRequestData(objectToJsonMapper.authenticatedUserListRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		AuthenticatedUserListResponseDTO responseDTO=new AuthenticatedUserListResponseDTO();
		List<AuthenticatedUser> authenticatedUserList= new LinkedList<AuthenticatedUser>();
		List<AuthenticatedUser> authenticatedTopUserList= new LinkedList<AuthenticatedUser>();
		List<AuthenticatedUser> authenticatedBottomUserList= new LinkedList<AuthenticatedUser>();
		try
		{
			// Creating the string for Month
			String date=requestDTO.getYear()+"-";
			if(requestDTO.getMonth().length()==1)
				date+="0"+requestDTO.getMonth()+"-";
			else
				date+=requestDTO.getMonth()+"-";
			
			String date1=date+"01T00:00:00.000";
			String date2=date;
			int month=Integer.parseInt(requestDTO.getMonth());
			int year=Integer.parseInt(requestDTO.getYear());
			if(month==1 || month==3 || month==5 || month==7 || month==8 || month==10 || month==12)
				date2+="31T23:59:59.999";
			else if(month==4 || month==6 || month==9 || month==11)
				date2+="30T23:59:59.999";
			else
			{
				if(java.time.Year.of(year).isLeap()==true)
					date2+="29T23:59:59.999";
				else
					date2+="28T23:59:59.999";
			}
			
			LocalDateTime dateTime1 = LocalDateTime.parse(date1);
			LocalDateTime dateTime2 = LocalDateTime.parse(date2);
		    List<AuthenticationLogEntity> unfilteredAuthenticatedUserLists=authenticationLogRepository.findAllAuthenticatedUsersOnMonth(dateTime1, dateTime2, requestDTO.getAppId());
		    // Extracting unique users
		 	Set<String> uniqueUsers = new HashSet<String>();
		 	for(AuthenticationLogEntity authenticationLogEntity: unfilteredAuthenticatedUserLists) {
		 		uniqueUsers.add(authenticationLogEntity.getLoginId());
		 	}
		 	
		 	if(requestDTO.getTopwise()!=null && requestDTO.getTopwise()==true)
		    {
		    	// for top users
		 		for (String loginId : uniqueUsers)
			    {
			    	AuthenticatedUser authenticatedUser=new AuthenticatedUser();
			    	long count=0;
			    	for(AuthenticationLogEntity authenticationLogEntity: unfilteredAuthenticatedUserLists)
			    	{
			    		if(authenticationLogEntity.getLoginId().equals(loginId))
			    			count++;
			    	}
			    	authenticatedUser.setLoginId(loginId);
			    	authenticatedUser.setFrequency(count);
			    	authenticatedTopUserList.add(authenticatedUser);
			    }
			    authenticatedTopUserList.sort(Comparator.comparing(AuthenticatedUser::getFrequency, Comparator.reverseOrder()));
		    	for(int i=0;i<authenticatedTopUserList.size() && i<requestDTO.getTopNo();i++)
		    	{
		    		authenticatedUserList.add(authenticatedTopUserList.get(i));
		    	}
		    }
		    else if(requestDTO.getBottomwise()!=null && requestDTO.getBottomwise()==true)
		    {
		    	// for bottom users
		    	for (String loginId : uniqueUsers)
			    {
		    		AuthenticatedUser authenticatedUser=new AuthenticatedUser();
			    	long count=0;
			    	for(AuthenticationLogEntity authenticationLogEntity: unfilteredAuthenticatedUserLists)
			    	{
			    		if(authenticationLogEntity.getLoginId().equals(loginId))
			    			count++;
			    	}
			    	authenticatedUser.setLoginId(loginId);
			    	authenticatedUser.setFrequency(count);
			    	authenticatedBottomUserList.add(authenticatedUser);
			    }
		    	authenticatedBottomUserList.sort(Comparator.comparing(AuthenticatedUser::getFrequency));
		    	for(int i=0;i<authenticatedBottomUserList.size() && i<requestDTO.getBottomNo();i++)
		    	{
		    		authenticatedUserList.add(authenticatedBottomUserList.get(i));
		    	}
		    }
		    else
		    {
		    	// for showing all users list
		    	for(AuthenticationLogEntity authenticationLogEntity: unfilteredAuthenticatedUserLists)
			    {
			    	AuthenticatedUser authenticatedUser=new AuthenticatedUser();
			    	authenticatedUser.setLoginId(authenticationLogEntity.getLoginId());
			    	authenticatedUser.setAccessedDate(Date.from(authenticationLogEntity.getAuthenticatedTimestamp().toInstant(ZoneOffset.UTC)));
			    	authenticatedUserList.add(authenticatedUser);
			    }
		    }
		 	
		    responseDTO.setAuthenticatedUserList(authenticatedUserList);
		    responseDTO.setMsg("Fetched user list successfully!");
		    responseDTO.setStatus(true);
		}
		catch(Exception e)
		{
			responseDTO.setMsg("user list fetching unsuccessful!");
		    responseDTO.setStatus(false);
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.authenticatedUserListResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}

	@Override
	public AuthenticatedUserListResponseDTO authenticatedUserListOnYear(AuthenticatedUserListRequestDTO requestDTO)
			throws Exception {
		// TODO Auto-generated method stub
		ObjectToJsonMapper objectToJsonMapper=new ObjectToJsonMapper();
		APIRequestEntity apiRequestEntity =new APIRequestEntity();
		apiRequestEntity.setApiName("Get Authenticated User List On Year");
		apiRequestEntity.setRequestData(objectToJsonMapper.authenticatedUserListRequestToJson(requestDTO));
		Instant instant = Instant.ofEpochMilli(new Date().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
		apiRequestEntity.setTimestamp(ldt);
		AuthenticatedUserListResponseDTO responseDTO=new AuthenticatedUserListResponseDTO();
		List<AuthenticatedUser> authenticatedUserList= new LinkedList<AuthenticatedUser>();
		List<AuthenticatedUser> authenticatedTopUserList= new LinkedList<AuthenticatedUser>();
		List<AuthenticatedUser> authenticatedBottomUserList= new LinkedList<AuthenticatedUser>();
		try
		{
			// Creating the string for Year
			String date=requestDTO.getYear()+"-";
			
			String date1=date+"01-01T00:00:00.000";
			String date2=date+"12-31T23:59:59.999";;
			
			LocalDateTime dateTime1 = LocalDateTime.parse(date1);
			LocalDateTime dateTime2 = LocalDateTime.parse(date2);
		    List<AuthenticationLogEntity> unfilteredAuthenticatedUserLists=authenticationLogRepository.findAllAuthenticatedUsersOnYear(dateTime1, dateTime2, requestDTO.getAppId());
		    // Extracting unique users
		 	Set<String> uniqueUsers = new HashSet<String>();
		 	for(AuthenticationLogEntity authenticationLogEntity: unfilteredAuthenticatedUserLists) {
		 		uniqueUsers.add(authenticationLogEntity.getLoginId());
		 	}
		 	
		 	if(requestDTO.getTopwise()!=null && requestDTO.getTopwise()==true)
		    {
		    	// for top users
		 		for (String loginId : uniqueUsers)
			    {
			    	AuthenticatedUser authenticatedUser=new AuthenticatedUser();
			    	long count=0;
			    	for(AuthenticationLogEntity authenticationLogEntity: unfilteredAuthenticatedUserLists)
			    	{
			    		if(authenticationLogEntity.getLoginId().equals(loginId))
			    			count++;
			    	}
			    	authenticatedUser.setLoginId(loginId);
			    	authenticatedUser.setFrequency(count);
			    	authenticatedTopUserList.add(authenticatedUser);
			    }
			    authenticatedTopUserList.sort(Comparator.comparing(AuthenticatedUser::getFrequency, Comparator.reverseOrder()));
		    	for(int i=0;i<authenticatedTopUserList.size() && i<requestDTO.getTopNo();i++)
		    	{
		    		authenticatedUserList.add(authenticatedTopUserList.get(i));
		    	}
		    }
		    else if(requestDTO.getBottomwise()!=null && requestDTO.getBottomwise()==true)
		    {
		    	// for bottom users
		    	for (String loginId : uniqueUsers)
			    {
		    		AuthenticatedUser authenticatedUser=new AuthenticatedUser();
			    	long count=0;
			    	for(AuthenticationLogEntity authenticationLogEntity: unfilteredAuthenticatedUserLists)
			    	{
			    		if(authenticationLogEntity.getLoginId().equals(loginId))
			    			count++;
			    	}
			    	authenticatedUser.setLoginId(loginId);
			    	authenticatedUser.setFrequency(count);
			    	authenticatedBottomUserList.add(authenticatedUser);
			    }
		    	authenticatedBottomUserList.sort(Comparator.comparing(AuthenticatedUser::getFrequency));
		    	for(int i=0;i<authenticatedBottomUserList.size() && i<requestDTO.getBottomNo();i++)
		    	{
		    		authenticatedUserList.add(authenticatedBottomUserList.get(i));
		    	}
		    }
		    else
		    {
		    	// for showing all users list
		    	for(AuthenticationLogEntity authenticationLogEntity: unfilteredAuthenticatedUserLists)
			    {
			    	AuthenticatedUser authenticatedUser=new AuthenticatedUser();
			    	authenticatedUser.setLoginId(authenticationLogEntity.getLoginId());
			    	authenticatedUser.setAccessedDate(Date.from(authenticationLogEntity.getAuthenticatedTimestamp().toInstant(ZoneOffset.UTC)));
			    	authenticatedUserList.add(authenticatedUser);
			    }
		    }
		 	
		    responseDTO.setAuthenticatedUserList(authenticatedUserList);
		    responseDTO.setMsg("Fetched user list successfully!");
		    responseDTO.setStatus(true);
		}
		catch(Exception e)
		{
			responseDTO.setMsg("user list fetching unsuccessful!");
		    responseDTO.setStatus(false);
		}
		apiRequestEntity.setResponseData(objectToJsonMapper.authenticatedUserListResponseToJson(responseDTO));
		apiRequestEntity.setStatus(responseDTO.getStatus());
		apiRequestRepository.save(apiRequestEntity);
		return responseDTO;
	}
	
	
	public Boolean sendAppDetailsMail(String email, Integer appId, String appName, String appShortCode, String verificationCode) throws Exception {
		Properties prop = new Properties();
		prop.put("mail.smtp.auth", auth);
		prop.put("mail.smtp.starttls.enable", enable);
		prop.put("mail.smtp.host", host);
		prop.put("mail.smtp.port", port);
		
		Session session = Session.getInstance(prop, new Authenticator() {
		    @Override
		    protected PasswordAuthentication getPasswordAuthentication() {
		        return new PasswordAuthentication(username, password);
		    }
		});
		Message message = new MimeMessage(session);
		try
		{
			message.setFrom(new InternetAddress(username,false));
			message.setRecipients(
					Message.RecipientType.TO, InternetAddress.parse(email));
			
			// Encrypting verification code
			verificationCode=encrypt(verificationCode);
			verificationCode=replaceBase64Char(verificationCode);
			
			message.setSubject("Set the password & the credentials for your Login Services- for Application, namely "+appName);
			
			
			String htmlContent="<div><span class='il'>Dear </span><span class='il'>Sir</span>/<span class='il'>Madam</span>,";
			htmlContent+="<p>Thanks for subscribing the login services for the application, namely <b>"+appName+"</b>.</p>";
			htmlContent+="<p>This email is regarding your details of subscribed application <b>"+appName+"</b>.</p>";
			htmlContent+="<p>Please find below details:<p>";
			htmlContent+="<p>1. User id: "+email+"</p>";
			htmlContent+="<p>2. Application id: "+appId+"</p>";
			htmlContent+="<p>3. Application name: "+appName+"</p>";
			htmlContent+="<p>4. Application code: "+appShortCode+"</p>";
			htmlContent+="<p>5. Kindly set your password by clicking the link given below: </p>";
			htmlContent+="<a href="+"http://localhost:4200/set-password?key="+verificationCode+ " style='word-break: break-all;'"+" target='_blank'>"+"http://localhost:4200/set-password?key="+verificationCode+"</a>";
			htmlContent+="<p>6. On clicking the link you will be redirected to new page to set password.</p><br>";
			htmlContent+="<p>This is a System Generated Email, Please Don't Reply.</p>";
			htmlContent+="<p>Thank you,<p>";
			htmlContent+="<p>CBN Team</p>";
			
			MimeBodyPart messageBodyPart = new MimeBodyPart(); 
			messageBodyPart.setContent(htmlContent, "text/html");

			Multipart multipart = new MimeMultipart();
			multipart.addBodyPart(messageBodyPart);
			message.setContent(multipart);
			Transport.send(message);
			return true;
		}
		catch(Exception e)
		{
			return false;
		}
	}
	
	public Boolean sendOTPToAppAdmin(String otp, String ref,String mobNo)
	{
		Twilio.init(APIConstants.ACCOUNT_SID, APIConstants.AUTH_TOKEN);
		String msg="OTP for admin verification for creation of application on CBN is:"+otp+" for request no Ref"+ref+" .The otp expires within 10 mins.";
		try
		{
			com.twilio.rest.api.v2010.account.Message.creator(new PhoneNumber(mobNo),new PhoneNumber(APIConstants.FROM_NUMBER), msg).create();
		}
		catch(Exception e)
		{
			System.out.println("OTP sent failed!");
			return false;
		}
		return true;
	}
	
	public KeyPair generateKeyPair(String algorithm, Integer keySize)
	{
		KeyPair pair=null;
		try
		{
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(algorithm);
			keyPairGen.initialize(keySize);
			pair = keyPairGen.generateKeyPair();
		}
		catch(Exception e)
		{
		}
		return pair;
	}
	
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
	
	public int getRandomNumber(int min, int max) {
        Random random = new Random();
        return random.nextInt(max - min) + min;
    }
	
	public Boolean sendOTP(String otp, String ref,String mobNo)
	{
		Twilio.init(APIConstants.ACCOUNT_SID, APIConstants.AUTH_TOKEN);
		String msg="OTP for verification for creation of application on CBN is:"+otp+" for request no Ref"+ref+" .The otp expires within 10 mins.";
		try
		{
			com.twilio.rest.api.v2010.account.Message.creator(new PhoneNumber(mobNo),new PhoneNumber(APIConstants.FROM_NUMBER), msg).create();
		}
		catch(Exception e)
		{
			System.out.println("OTP sent failed!");
			return false;
		}
		return true;
	}
	
	public String getRandomStringForVerificationCode(int len)
	{
		 StringBuilder sb = new StringBuilder(len);
		 for(int i = 0; i < len; i++)
		    sb.append(APIConstants.generatorForVerificationCode.charAt(rnd.nextInt(APIConstants.generatorForVerificationCode.length())));
		 return sb.toString();
	}
	
	public String encrypt(String data) throws Exception {
        byte[] dataInBytes = data.getBytes();
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = encryptionCipher.doFinal(dataInBytes);
        return encode(encryptedBytes);
    }
	
	public String decrypt(String encryptedData) throws Exception {
        byte[] dataInBytes = decode(encryptedData);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(APIConstants.DATA_LENGTH, encryptionCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(dataInBytes);
        return new String(decryptedBytes);
    }
	
	private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }
    
    private String replaceBase64Char(String code)
    {
    	for(int i=0;i<code.length();i++)
		{
			if(code.charAt(i)=='+')
			{
				code=code.substring(0, i)+'@'+code.substring(i+1, code.length());
			}
			else if(code.charAt(i)=='/')
				code=code.substring(0, i)+'$'+code.substring(i+1, code.length());
			else if(code.charAt(i)=='=')
				code=code.substring(0, i)+'#'+code.substring(i+1, code.length());
		}
    	return code;
    }

    private String replaceAddedChar(String code)
    {
    	for(int i=0;i<code.length();i++)
		{
			if(code.charAt(i)=='@')
			{
				code=code.substring(0, i)+'+'+code.substring(i+1, code.length());
			}
			else if(code.charAt(i)=='$')
				code=code.substring(0, i)+'/'+code.substring(i+1, code.length());
			else if(code.charAt(i)=='#')
				code=code.substring(0, i)+'='+code.substring(i+1, code.length());
		}
    	return code;
    }

}
