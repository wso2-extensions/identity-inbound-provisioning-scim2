/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.scim2.common.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpStatus;
import org.wso2.carbon.identity.scim2.common.extenstion.SCIMUserStoreErrorResolver;
import org.wso2.carbon.identity.scim2.common.extenstion.SCIMUserStoreException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreClientException;
import org.wso2.carbon.user.core.constants.UserCoreErrorConstants;

import static org.wso2.carbon.user.core.constants.UserCoreErrorConstants.ErrorMessages.ERROR_CODE_GROUP_ALREADY_EXISTS;

/**
 * Default implementation of SCIMUserStoreErrorResolver. Should be used to resolve errors thrown by default
 * user store managers packed in the product.
 */
public class DefaultSCIMUserStoreErrorResolver implements SCIMUserStoreErrorResolver {

    private static final String ERROR_CODE_READ_ONLY_USERSTORE = "30002";
    private static final String ERROR_CODE_USER_NOT_FOUND = "30007";
    private static final String ERROR_CODE_EXISTING_ROLE_NAME = "30012";

    @Override
    public SCIMUserStoreException resolve(UserStoreException e) {

        if (e.getMessage().contains(ERROR_CODE_USER_NOT_FOUND)) {
            String msg = e.getMessage().substring(e.getMessage().indexOf(":") + 1).trim();
            return new SCIMUserStoreException(msg, HttpStatus.SC_NOT_FOUND);
        } else if (e.getMessage().contains(ERROR_CODE_EXISTING_ROLE_NAME) ||
                (e instanceof org.wso2.carbon.user.core.UserStoreClientException &&
                        ((UserStoreClientException) e).getErrorCode() != null &&
                        ((UserStoreClientException) e).getErrorCode()
                                .contains(ERROR_CODE_GROUP_ALREADY_EXISTS.getCode()))) {
            String groupName = e.getMessage().substring(e.getMessage().indexOf(":") + 1).trim().split("\\s+")[0];
            String msg =
                    "Group name: " + groupName + " is already there in the system. Please pick another group name.";
            return new SCIMUserStoreException(msg, HttpStatus.SC_CONFLICT);
        } else if (e.getMessage().contains(ERROR_CODE_READ_ONLY_USERSTORE) ||
                (e instanceof org.wso2.carbon.user.core.UserStoreException && StringUtils
                        .equals(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_READONLY_USER_STORE.getCode(),
                                ((org.wso2.carbon.user.core.UserStoreException) e).getErrorCode()))) {
            String msg = "Invalid operation. User store is read only";
            return new SCIMUserStoreException(msg, HttpStatus.SC_BAD_REQUEST);
        } else if (e instanceof org.wso2.carbon.user.core.UserStoreException && StringUtils
                .equals(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_USERNAME_CANNOT_BE_EMPTY.getCode(),
                        ((org.wso2.carbon.user.core.UserStoreException) e).getErrorCode())) {
            return new SCIMUserStoreException("Unable to create the user. Username is a mandatory field.",
                    HttpStatus.SC_BAD_REQUEST);
        } else if (e instanceof org.wso2.carbon.user.core.UserStoreClientException && UserCoreErrorConstants
                .ErrorMessages.ERROR_CODE_INVALID_DOMAIN_NAME.getCode().equals(((UserStoreClientException) e)
                        .getErrorCode())) {
            return new SCIMUserStoreException("Unable to proceed. Invalid domain name.", HttpStatus.SC_BAD_REQUEST);
        } else if (e instanceof org.wso2.carbon.user.core.UserStoreClientException) {
            String description = e.getMessage();
            if (StringUtils.isBlank(description)) {
                description = "Invalid Request";
            }
            return new SCIMUserStoreException(description, HttpStatus.SC_BAD_REQUEST);
        }
        return null;
    }

    @Override
    public int getOrder() {

        return 0;
    }
}
