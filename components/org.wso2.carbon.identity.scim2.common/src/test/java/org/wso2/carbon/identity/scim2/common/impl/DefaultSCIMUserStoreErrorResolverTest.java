/*
 * Copyright (c) 2021, WSO2 LLC. (http://www.wso2.org)
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
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.scim2.common.extenstion.SCIMUserStoreException;
import org.wso2.carbon.user.api.UserStoreException;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

/**
 * Contains the unit test cases for DefaultSCIMUserStoreErrorResolver.
 */
public class DefaultSCIMUserStoreErrorResolverTest {

    @Test
    public void testGetOrder() {

        DefaultSCIMUserStoreErrorResolver defaultSCIMUserStoreErrorResolver = new DefaultSCIMUserStoreErrorResolver();
        assertEquals(defaultSCIMUserStoreErrorResolver.getOrder(), 0);
    }

    @DataProvider(name = "dataProviderForResolveUserNameMandatory")
    public Object[][] dataProviderForResolveUserNameMandatory() {

        return new Object[][]{
                {new UserStoreException("error: 30007"), HttpStatus.SC_NOT_FOUND},
                {new org.wso2.carbon.user.core.UserStoreException("error", "32102"), HttpStatus.SC_BAD_REQUEST},
                {new org.wso2.carbon.user.core.UserStoreClientException("error", "32103"), HttpStatus.SC_BAD_REQUEST},
                {new org.wso2.carbon.user.core.UserStoreClientException("error", "321xx"), HttpStatus.SC_BAD_REQUEST},
                {new org.wso2.carbon.user.core.UserStoreClientException("30012 - error", "xxx"), HttpStatus.SC_CONFLICT},
                {new org.wso2.carbon.user.core.UserStoreClientException("error", "65019"), HttpStatus.SC_CONFLICT},
                {new org.wso2.carbon.user.core.UserStoreClientException("error"), HttpStatus.SC_BAD_REQUEST},
        };
    }

    @Test(dataProvider = "dataProviderForResolveUserNameMandatory")
    public void testResolveHappyPath(Object userStoreException, int expected) {

        DefaultSCIMUserStoreErrorResolver defaultSCIMUserStoreErrorResolver = new DefaultSCIMUserStoreErrorResolver();
        SCIMUserStoreException scimUserStoreException = defaultSCIMUserStoreErrorResolver.
                resolve((UserStoreException) userStoreException);
        assertEquals(scimUserStoreException.getHttpStatusCode(), expected);
    }

    @DataProvider(name = "dataProviderForResolveUnHappyPath")
    public Object[][] dataProviderForResolveUnHappyPath() {

        return new Object[][]{
                {new UserStoreException("error: 30008")},
                {new org.wso2.carbon.user.core.UserStoreException("error", "32103")}
        };
    }

    @Test(dataProvider = "dataProviderForResolveUnHappyPath")
    public void testResolveUnHappyPath(Object userStoreException) {

        DefaultSCIMUserStoreErrorResolver defaultSCIMUserStoreErrorResolver = new DefaultSCIMUserStoreErrorResolver();
        SCIMUserStoreException scimUserStoreException = defaultSCIMUserStoreErrorResolver.
                resolve((UserStoreException) userStoreException);
        assertNull(scimUserStoreException);
    }
}
