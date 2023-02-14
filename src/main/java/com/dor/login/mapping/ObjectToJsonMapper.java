package com.dor.login.mapping;

import java.io.IOException;

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
import com.fasterxml.jackson.databind.ObjectMapper;

public class ObjectToJsonMapper {
	
	public String abstractRequestToJson(AbstractRequestDTO requestDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(requestDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String abstractResponseToJson(AbstractResponseDTO responseDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(responseDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String loginRequestToJson(LoginRequestDTO requestDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(requestDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String loginResponseToJson(LoginResponseDTO responseDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(responseDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String loginOTPResponseToJson(LoginOTPResponseDTO responseDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(responseDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String forgetPasswordOTPRequestToJson(ForgetPasswordOTPRequestDTO requestDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(requestDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String forgetPasswordOTPResponseToJson(ForgetPasswordOTPResponseDTO responseDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(responseDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String forgetPasswordOTPValidationResponseToJson(ForgetPasswordOTPValidationResponseDTO responseDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(responseDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String setPasswordRequestToJson(SetPasswordRequestDTO requestDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(requestDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String changePasswordOTPRequestToJson(ChangePasswordOTPRequestDTO requestDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(requestDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String changePasswordOTPResponseToJson(ChangePasswordOTPResponseDTO responseDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(responseDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String changePasswordOTPValidationResponseToJson(ChangePasswordOTPValidationResponseDTO responseDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(responseDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String addApplRequestToJson(AddRemoveApplRequestDTO requestDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(requestDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String applicationCreationRequestToJson(ApplicationCreationRequestDTO requestDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(requestDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String applicationResponseToJson(ApplicationResponseDTO responseDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(responseDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String userCreationRequestToJson(UserCreationRequestDTO requestDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(requestDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String sendOTPRequestToJson(SendOTPRequestDTO requestDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(requestDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String sendOTPResponseToJson(SendOTPResponseDTO responseDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(responseDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String verifyAdminOTPRequestToJson(VerifyAdminOTPRequestDTO requestDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(requestDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String mobileVerificationRequestToJson(MobileVerificationRequestDTO requestDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(requestDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String userInfoResponseToJson(UserInfoResponseDTO responseDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(responseDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String authenticatedUserListRequestToJson(AuthenticatedUserListRequestDTO requestDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(requestDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}
	
	public String authenticatedUserListResponseToJson(AuthenticatedUserListResponseDTO responseDTO)
	{
		ObjectMapper Obj = new ObjectMapper();  
        try {  
            String jsonObject = Obj.writeValueAsString(responseDTO); 
            return jsonObject;
        }  
        catch (IOException e) {  
            return null;
        }  
	}

}
