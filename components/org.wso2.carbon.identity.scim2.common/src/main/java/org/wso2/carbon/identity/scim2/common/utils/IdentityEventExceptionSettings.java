/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.scim2.common.utils;

import java.util.ArrayList;
import java.util.List;

/**
 * this class is the blue print of IdentityEventException settings used in SCIMUserManager.
 */
public class IdentityEventExceptionSettings {
    private boolean exposeErrorCodeInMessage;
    private List<String> badRequestErrorCodes = new ArrayList<>();

	public boolean isExposeErrorCodeInMessage() {
		return exposeErrorCodeInMessage;
	}

	public void setExposeErrorCodeInMessage(boolean exposeErrorCodeInMessage) {
		this.exposeErrorCodeInMessage = exposeErrorCodeInMessage;
	}

	public List<String> getBadRequestErrorCodes() {
		return badRequestErrorCodes;
	}

	public void setBadRequestErrorCodes(List<String> badRequestErrorCodes) {
		this.badRequestErrorCodes = badRequestErrorCodes;
	}
}


