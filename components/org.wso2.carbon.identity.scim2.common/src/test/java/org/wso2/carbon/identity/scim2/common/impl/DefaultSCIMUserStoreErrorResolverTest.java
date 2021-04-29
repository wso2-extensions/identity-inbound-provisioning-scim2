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

    @DataProvider(name = "dpResolveUserNotFound")
    public Object[][] dpResolveUserNotFound() {

        return new Object[][]{
                {"error: 30007", "30007", HttpStatus.SC_NOT_FOUND},
        };
    }

    @Test(dataProvider = "dpResolveUserNotFound")
    public void testResolveUserNotFound(String message, String checkMessage, int checkCode) {

        UserStoreException userStoreException = new UserStoreException(message);
        DefaultSCIMUserStoreErrorResolver defaultSCIMUserStoreErrorResolver = new DefaultSCIMUserStoreErrorResolver();
        SCIMUserStoreException scimUserStoreException = defaultSCIMUserStoreErrorResolver.resolve(userStoreException);

        assertEquals(checkCode, scimUserStoreException.getHttpStatusCode());
        assertEquals(checkMessage, scimUserStoreException.getMessage());
    }

    @DataProvider(name = "dpResolveUserNameMandatory")
    public Object[][] dpResolveUserNameMandatory() {

        return new Object[][]{
                {"error", "32102", "Unable to create the user. Username is a mandatory field.", HttpStatus.SC_BAD_REQUEST},

        };
    }

    @Test(dataProvider = "dpResolveUserNameMandatory")
    public void testResolveUserNameMandatory(String message, String errorCode, String checkMessage, int checkCode) {

        UserStoreException userStoreException = new org.wso2.carbon.user.core.UserStoreException(message, errorCode);
        DefaultSCIMUserStoreErrorResolver defaultSCIMUserStoreErrorResolver = new DefaultSCIMUserStoreErrorResolver();
        SCIMUserStoreException scimUserStoreException = defaultSCIMUserStoreErrorResolver.resolve(userStoreException);

        assertEquals(checkCode, scimUserStoreException.getHttpStatusCode());
        assertEquals(checkMessage, scimUserStoreException.getMessage());

    }

    @DataProvider(name = "dpResolveInvalidDomainName")
    public Object[][] dpResolveInvalidDomainName() {

        return new Object[][]{
                {"error", "32103", "Unable to proceed. Invalid domain name.", HttpStatus.SC_BAD_REQUEST},
        };
    }

    @Test(dataProvider = "dpResolveInvalidDomainName")
    public void testResolveInvalidDomainName(String message, String errorCode, String checkMessage, int checkCode) {

        UserStoreException userStoreException = new org.wso2.carbon.user.core.UserStoreClientException(message, errorCode);
        DefaultSCIMUserStoreErrorResolver defaultSCIMUserStoreErrorResolver = new DefaultSCIMUserStoreErrorResolver();
        SCIMUserStoreException scimUserStoreException = defaultSCIMUserStoreErrorResolver.resolve(userStoreException);

        assertEquals(checkCode, scimUserStoreException.getHttpStatusCode());
        assertEquals(checkMessage, scimUserStoreException.getMessage());

    }

    @DataProvider(name = "dpResolveNullCheck")
    public Object[][] dpResolveNullCheck() {

        return new Object[][]{
                {"", "error: 30008", "30008"},
                {"coreUserStoreException", "error", "32103"},
                {"coreUserStoreClientException", "error", "32104"},
        };
    }

    @Test(dataProvider = "dpResolveNullCheck")
    public void testResolveNullCheck(String type, String message, String errorCode) {

        UserStoreException userStoreException;
        switch (type) {
            case "coreUserStoreException":
                userStoreException = new org.wso2.carbon.user.core.UserStoreException(message, errorCode);
                break;
            case "coreUserStoreClientException":
                userStoreException = new org.wso2.carbon.user.core.UserStoreClientException(message, errorCode);
                break;
            default:
                userStoreException = new UserStoreException(message);
                break;
        }
        DefaultSCIMUserStoreErrorResolver defaultSCIMUserStoreErrorResolver = new DefaultSCIMUserStoreErrorResolver();
        SCIMUserStoreException scimUserStoreException = defaultSCIMUserStoreErrorResolver.resolve(userStoreException);

        assertNull(scimUserStoreException);

    }
}