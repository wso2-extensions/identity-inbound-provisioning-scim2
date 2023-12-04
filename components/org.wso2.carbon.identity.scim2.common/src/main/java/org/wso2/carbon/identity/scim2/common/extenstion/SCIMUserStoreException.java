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

package org.wso2.carbon.identity.scim2.common.extenstion;

import org.wso2.carbon.identity.base.IdentityException;

/**
 * This exception is used in the SCIM User Store Error Resolver extension point, to return any internal errors to
 * the SCIM API layer. Since SCIM API returns only an error message (detail) and http error code, this
 * exception is designed to accept only those two.
 */
public class SCIMUserStoreException extends IdentityException {

    private static final long serialVersionUID = 3477076930782578976L;
    private final int httpStatusCode;

    public SCIMUserStoreException(String errorMessage, int httpStatusCode) {

        super(errorMessage);
        this.httpStatusCode = httpStatusCode;
    }

    public int getHttpStatusCode() {

        return httpStatusCode;
    }
}
