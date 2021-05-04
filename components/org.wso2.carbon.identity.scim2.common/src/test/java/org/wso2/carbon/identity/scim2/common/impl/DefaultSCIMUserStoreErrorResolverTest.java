/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.scim2.common.impl;

import org.apache.http.HttpStatus;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.scim2.common.extenstion.SCIMUserStoreException;
import org.wso2.carbon.user.api.UserStoreException;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

public class DefaultSCIMUserStoreErrorResolverTest extends PowerMockTestCase {

    @Test
    public void testGetOrder() {

        DefaultSCIMUserStoreErrorResolver defaultSCIMUserStoreErrorResolver = new DefaultSCIMUserStoreErrorResolver();
        assertEquals(defaultSCIMUserStoreErrorResolver.getOrder(), 0);
    }

    @DataProvider(name = "dataProviderForResolveUserNameMandatory")
    public Object[][] dataProviderForResolveUserNameMandatory() {

        return new Object[][]{
                {"error: 30007", "", HttpStatus.SC_NOT_FOUND, "", false},
                {"error", "32102", HttpStatus.SC_BAD_REQUEST, "coreUserStoreException", false},
                {"error", "32103", HttpStatus.SC_BAD_REQUEST, "coreUserStoreClientException", false},
                {"error: 30008", "", HttpStatus.SC_NOT_FOUND, "", true},
                {"error", "32103", HttpStatus.SC_BAD_REQUEST, "coreUserStoreException", true},
                {"error", "32104", HttpStatus.SC_BAD_REQUEST, "coreUserStoreClientException", true},
        };
    }

    @Test(dataProvider = "dataProviderForResolveUserNameMandatory")
    public void testResolveUserNameMandatory(String message, String errorCode, int checkCode, String errorType,
                                             boolean isNullExcepted) {

        UserStoreException userStoreException;
        switch (errorType) {
            case "coreUserStoreException":
                userStoreException = new org.wso2.carbon.user.core.UserStoreException(message, errorCode);
                break;
            case "coreUserStoreClientException":
                userStoreException = new org.wso2.carbon.user.core.UserStoreClientException(message, errorCode);
                break;
            default:
                userStoreException = new UserStoreException(message);
        }

        DefaultSCIMUserStoreErrorResolver defaultSCIMUserStoreErrorResolver = new DefaultSCIMUserStoreErrorResolver();
        SCIMUserStoreException scimUserStoreException = defaultSCIMUserStoreErrorResolver.resolve(userStoreException);
        if (isNullExcepted) {
            assertNull(scimUserStoreException);
        } else {
            assertEquals(checkCode, scimUserStoreException.getHttpStatusCode());
        }
    }
}
