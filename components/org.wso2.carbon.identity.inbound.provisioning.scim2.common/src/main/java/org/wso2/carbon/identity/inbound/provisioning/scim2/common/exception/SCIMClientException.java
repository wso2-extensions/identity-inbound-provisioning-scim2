/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.inbound.provisioning.scim2.common.exception;

/**
 * This class is an extension of {@code Exception} class and used to indicate SCIM2 related exceptions.
 *
 * @since 1.0.0
 */
public class SCIMClientException extends Exception {
    private static final long serialVersionUID = -6057036683816666255L;
    private int errorCode;

    public SCIMClientException() {
    }

    public SCIMClientException(String message, Throwable cause) {
        super(message, cause);
    }

    public SCIMClientException(String message, Throwable cause, int errorCode) {
        super(message, cause);
        setErrorCode(errorCode);
    }

    public SCIMClientException(String message, boolean convertMessage) {
        super(message);
    }

    public SCIMClientException(String message, boolean convertMessage, int errorCode) {
        super(message);
        setErrorCode(errorCode);
    }

    public SCIMClientException(String message) {
        super(message);
    }

    public SCIMClientException(String message, int errorCode) {
        super(message);
        setErrorCode(errorCode);
    }

    public SCIMClientException(Throwable cause) {
        super(cause);
    }

    public SCIMClientException(Throwable cause, int errorCode) {
        super(cause);
        setErrorCode(errorCode);
    }

    public int getErrorCode() {
        return this.errorCode;
    }

    public void setErrorCode(int errorCode) {
        this.errorCode = errorCode;
    }
}
