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

import org.mockito.Mock;

import org.mockito.MockedStatic;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.charon3.core.exceptions.NotFoundException;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.assertEquals;
import static org.mockito.Mockito.mockStatic;

/**
 * Contains the unit test cases for IdentityResourceURLBuilder.
 */
public class IdentityResourceURLBuilderTest {

    private static final Map<String, String> DUMMY_ENDPOINT_URI_MAP = new HashMap<String, String>() {{
        put("Users", "https://localhost:9444/scim2/Users");
        put("Groups", "https://localhost:9444/scim2/Groups");
    }};

    @Mock
    ServiceURLBuilder mockServiceURLBuilder;

    @Mock
    ServiceURL mockServiceUrl;

    private MockedStatic<ServiceURLBuilder> serviceURLBuilder;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;

    @BeforeMethod
    public void setUpMethod() {

        initMocks(this);
        serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
        serviceURLBuilder.when(() -> ServiceURLBuilder.create()).thenReturn(mockServiceURLBuilder);
        when(mockServiceURLBuilder.addPath(anyString())).thenReturn(mockServiceURLBuilder);
        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
    }

    @DataProvider(name = "dataProviderForBuild")
    public Object[][] dataProviderForBuild() {

        return new Object[][]{
                {true, "https://localhost:9444/scim2/", "Users", false, "https://localhost:9444/scim2/Users"},
                {true, "https://localhost:9444/scim2/", "Groups", true, "https://localhost:9444/scim2/Groups"},
                {false, "https://localhost:9444/scim2/", "Users", false, "https://localhost:9444/scim2/Users"},
                {true, "https://localhost:9444/scim2/", "InvalidResource", true, null},
                {false, "https://localhost:9444/scim2/", "InvalidResource", false, null},
        };
    }

    @Test(dataProvider = "dataProviderForBuild")
    public void testBuild(boolean isTenantQualifiedUrlsEnabled, String url, String resource, boolean throwError,
                          String expected) throws NotFoundException, URLBuilderException {

        identityTenantUtil.when(() -> IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifiedUrlsEnabled);
        when(mockServiceURLBuilder.build()).thenAnswer(invocationOnMock -> {
            if (throwError) {
                throw new URLBuilderException("Protocol of service URL is not available.");
            }
            return mockServiceUrl;
        });
        when(mockServiceUrl.getAbsolutePublicURL()).thenReturn(url);
        IdentityResourceURLBuilder identityResourceURLBuilder = new IdentityResourceURLBuilder();
        identityResourceURLBuilder.setEndpointURIMap(DUMMY_ENDPOINT_URI_MAP);
        String buildValue = identityResourceURLBuilder.build(resource);
        assertEquals(buildValue, expected);
    }

    @DataProvider(name = "dataProviderForBuildThrowingNotFoundException")
    public Object[][] dataProviderForBuildThrowingNotFoundException() {

        return new Object[][]{
                {true, "InvalidResource"},
                {false, "InvalidResource"},
        };
    }

    @Test(expectedExceptions = NotFoundException.class, dataProvider = "dataProviderForBuildThrowingNotFoundException")
    public void testBuildThrowingNotFoundException(boolean isTenantQualifiedUrlsEnabled, String resource)
            throws URLBuilderException, NotFoundException {

        identityTenantUtil.when(() -> IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifiedUrlsEnabled);
        when(mockServiceURLBuilder.build()).thenThrow(
                new URLBuilderException("Protocol of service URL is not available."));
        IdentityResourceURLBuilder identityResourceURLBuilder = new IdentityResourceURLBuilder();
        identityResourceURLBuilder.build(resource);
    }
}
