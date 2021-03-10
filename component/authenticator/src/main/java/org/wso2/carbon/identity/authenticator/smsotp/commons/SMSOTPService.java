package org.wso2.carbon.identity.authenticator.smsotp.commons;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.authenticator.smsotp.OneTimePassword;
import org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannels;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.identity.recovery.IdentityRecoveryException;
import org.wso2.carbon.identity.recovery.internal.IdentityRecoveryServiceDataHolder;
import org.wso2.carbon.identity.recovery.util.Utils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Properties;

import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.ErrorMessage.EXPIRED_OTP;
import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.ErrorMessage.INVALID_OTP;
import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.ErrorMessage.INVALID_OTP_USER;

public class SMSOTPService {

    private static final Log log = LogFactory.getLog(SMSOTPService.class);
    private static final String SESSION_TYPE_OTP = "SMS_OTP";
    ObjectMapper mapper = new ObjectMapper();

    public void proceedWithOTP(String mobileNumber, String username, String userStore,
                               String tenantDomain, String transactionID, Properties properties)
            throws AuthenticationFailedException {

        String tokenLengthValue = properties.getProperty("smsOtp.TokenLength");
        String tokenExpiryTimeValue = properties.getProperty("smsOtp.TokenExpiryTime");
        String isEnableAlphanumericTokenProperty = properties.getProperty("smsOtp.isEnableAlphanumericToken");
        boolean isEnableAlphanumericToken = false;

        if (isEnableAlphanumericTokenProperty != null) {
            isEnableAlphanumericToken = Boolean.parseBoolean(isEnableAlphanumericTokenProperty);
        }

        int tokenLength;
        long tokenExpiryTime = SMSOTPConstants.SMS_OTP_EXPIRY_TIME;
        try {
            OneTimePassword token = new OneTimePassword();
            if (tokenLengthValue != null) {
                tokenLength = Integer.parseInt(tokenLengthValue);
            } else {
                tokenLength = SMSOTPConstants.NUMBER_DIGIT;
            }
            if (tokenExpiryTimeValue != null) {
                tokenExpiryTime = Integer.parseInt(tokenExpiryTimeValue);
            }
            String otpToken = token.generateToken(transactionID, String.valueOf(SMSOTPConstants.NUMBER_BASE),
                    tokenLength, isEnableAlphanumericToken);
            /**
             * Save the otp in the IDN_AUTH_SESSION_STORE table
             */
            long sentOTPTokenTime = System.currentTimeMillis();
            SessionDTO sessionDTO = new SessionDTO();
            sessionDTO.setOtpToken(otpToken);
            sessionDTO.setGeneratedTime(sentOTPTokenTime);
            sessionDTO.setExpiryTime(tokenExpiryTime);
            sessionDTO.setTransactionID(transactionID);
            sessionDTO.setFullQualifiedUserName(userStore + "/" + username + "@" + tenantDomain);

            String jsonString = mapper.writeValueAsString(sessionDTO);

            SessionDataStore.getInstance().storeSessionData(transactionID, SESSION_TYPE_OTP, jsonString,
                    IdentityTenantUtil.getTenantId(tenantDomain));
            if (log.isDebugEnabled()) {
                log.debug("Generated OTP successfully and saved in the database...");
            }

            triggerNotification(username, tenantDomain, userStore, mobileNumber, otpToken);

        } catch (Exception e) {
            throw new AuthenticationFailedException("Error while sending the HTTP request. ", e);
        }
    }

    protected void triggerNotification(String userName, String tenantDomain, String userStoreDomainName,
                                       String mobileNumber, String otpCode) throws IdentityRecoveryException {

        String notificationType = IdentityRecoveryConstants.NOTIFICATION_TYPE_VERIFY_MOBILE_ON_UPDATE;

        if (log.isDebugEnabled()) {
            log.debug("Sending: " + notificationType + " notification to user: " + userStoreDomainName + "/"
                    + userName);
        }

        String eventName = IdentityEventConstants.Event.TRIGGER_SMS_NOTIFICATION;
        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, userName);
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, userStoreDomainName);
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, tenantDomain);
        properties.put(IdentityEventConstants.EventProperty.NOTIFICATION_CHANNEL,
                NotificationChannels.SMS_CHANNEL.getChannelType());
        properties.put(IdentityRecoveryConstants.TEMPLATE_TYPE, notificationType);

        if (StringUtils.isNotBlank(mobileNumber)) {
            properties.put(IdentityRecoveryConstants.SEND_TO, mobileNumber);
        }
        if (StringUtils.isNotBlank(otpCode)) {
            properties.put(IdentityRecoveryConstants.CONFIRMATION_CODE, otpCode);
        }

        Event identityMgtEvent = new Event(eventName, properties);
        try {
            IdentityRecoveryServiceDataHolder.getInstance().getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            throw Utils.handleServerException(IdentityRecoveryConstants.ErrorMessages.ERROR_CODE_TRIGGER_NOTIFICATION,
                    userStoreDomainName + "/" + userName + "@" + tenantDomain, e);
        }
    }

    public void validateOTP(String username, String tenantDomain, String transactionID, String OTP)
            throws IOException, IdentityEventException {
        String jsonString = (String) SessionDataStore.getInstance().getSessionData(transactionID, SESSION_TYPE_OTP);
        SessionDTO sessionDTO = mapper.readValue(jsonString, SessionDTO.class);

        if (System.currentTimeMillis() - sessionDTO.getGeneratedTime() >= sessionDTO.getExpiryTime()) {
            throw new IdentityEventException(EXPIRED_OTP.getCode(), EXPIRED_OTP.getMessage());
        } else {
            if (!(sessionDTO.getFullQualifiedUserName().equals(org.wso2.carbon.identity.mgt.util.Utils
                    .getUserStoreDomainName(username) + "/" + username + "@" + tenantDomain))) {
                throw new IdentityEventException(INVALID_OTP_USER.getCode(), INVALID_OTP_USER.getMessage());
            } else {
                if (!((sessionDTO.getTransactionID() + sessionDTO.getOtpToken()).equals(transactionID + OTP))) {
                    throw new IdentityEventException(INVALID_OTP.getCode(), INVALID_OTP.getMessage());
                }
            }
        }
    }

}
