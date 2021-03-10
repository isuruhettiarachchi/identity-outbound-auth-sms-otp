package org.wso2.carbon.identity.authenticator.smsotp.commons;

import org.codehaus.jackson.annotate.JsonProperty;

import java.util.Objects;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class SessionDTO {
    private static final long serialVersionUID = 1L;

    @NotNull
    @Valid
    private String otpToken;
    @NotNull
    @Valid
    private long generatedTime;
    @NotNull
    @Valid
    private long expiryTime;
    @NotNull
    @Valid
    private String transactionID;
    @NotNull
    @Valid
    private String fullQualifiedUserName;

    public String getOtpToken() {
        return otpToken;
    }

    @JsonProperty("otpToken")
    public void setOtpToken(String otpToken) {
        this.otpToken = otpToken;
    }

    @JsonProperty("generatedTime")
    public long getGeneratedTime() {
        return generatedTime;
    }

    public void setGeneratedTime(long generatedTime) {
        this.generatedTime = generatedTime;
    }

    @JsonProperty("expiryTime")
    public long getExpiryTime() {
        return expiryTime;
    }

    public void setExpiryTime(long expiryTime) {
        this.expiryTime = expiryTime;
    }

    @JsonProperty("transactionID")
    public String getTransactionID() {
        return transactionID;
    }

    public void setTransactionID(String transactionID) {
        this.transactionID = transactionID;
    }

    @JsonProperty("fullQualifiedUserName")
    public String getFullQualifiedUserName() {
        return fullQualifiedUserName;
    }

    public void setFullQualifiedUserName(String fullQualifiedUserName) {
        this.fullQualifiedUserName = fullQualifiedUserName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SessionDTO)) {
            return false;
        }
        SessionDTO that = (SessionDTO) o;
        return getGeneratedTime() == that.getGeneratedTime() &&
                getExpiryTime() == that.getExpiryTime() &&
                getOtpToken().equals(that.getOtpToken()) &&
                getTransactionID().equals(that.getTransactionID()) &&
                getFullQualifiedUserName().equals(that.getFullQualifiedUserName());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getOtpToken(), getGeneratedTime(), getExpiryTime(), getTransactionID(),
                getFullQualifiedUserName());
    }

    @Override
    public String toString() {
        return "SessionDTO{" +
                "otpToken='" + otpToken + '\'' +
                ", generatedTime=" + generatedTime +
                ", expiryTime=" + expiryTime +
                ", transactionID='" + transactionID + '\'' +
                ", fullQualifiedUserName='" + fullQualifiedUserName + '\'' +
                '}';
    }
}
