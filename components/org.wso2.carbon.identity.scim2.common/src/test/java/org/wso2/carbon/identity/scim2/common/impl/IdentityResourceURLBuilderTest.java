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
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.charon3.core.exceptions.NotFoundException;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

@PrepareForTest({IdentityTenantUtil.class, ServiceURLBuilder.class})
public class IdentityResourceURLBuilderTest extends PowerMockTestCase {

    private static final Map<String, String> DUMMY_ENDPOINT_URI_MAP = new HashMap<String, String>() {{
        put("resource", "www.default.url");
        put("resource2", "www.default2.url");
    }};

    @Mock
    ServiceURLBuilder mockServiceURLBuilder;

    @Mock
    ServiceURL mockServiceUrl;

    @BeforeMethod
    public void setUpMethod() {

        initMocks(this);
        mockStatic(ServiceURLBuilder.class);
        when(ServiceURLBuilder.create()).thenReturn(mockServiceURLBuilder);
        when(mockServiceURLBuilder.addPath(anyString())).thenReturn(mockServiceURLBuilder);
    }

    @Test
    public void testBuildTenantQualifiedUrlsEnabled() throws NotFoundException, URLBuilderException {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(true);
        when(mockServiceURLBuilder.build()).thenReturn(mockServiceUrl);
        when(mockServiceUrl.getAbsolutePublicURL()).thenReturn("www.public.url");
        IdentityResourceURLBuilder identityResourceURLBuilder = new IdentityResourceURLBuilder();
        String buildValue = identityResourceURLBuilder.build("resource");
        System.out.println(buildValue);
        assertEquals(buildValue, "www.public.url" + "resource");
    }

    @Test
    public void testBuildTenantQualifiedUrlsEnabledThrowURLBuilderException() throws NotFoundException {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(true);
        try {
            when(mockServiceURLBuilder.build()).thenThrow(
                    new URLBuilderException("Protocol of service URL is not available."));
        } catch (URLBuilderException e) {
            e.printStackTrace();
        }
        IdentityResourceURLBuilder identityResourceURLBuilder = new IdentityResourceURLBuilder();
        identityResourceURLBuilder.setEndpointURIMap(DUMMY_ENDPOINT_URI_MAP);
        String buildValue = identityResourceURLBuilder.build("resource");
        assertEquals(buildValue, "www.default.url");
        String buildValue2 = identityResourceURLBuilder.build("resource2");
        assertEquals(buildValue2, "www.default2.url");
    }

    @Test
    public void testBuildTenantQualifiedUrlsEnabledThrowURLBuilderExceptionThrowNotFoundException() {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(true);
        try {
            when(mockServiceURLBuilder.build()).thenThrow(
                    new URLBuilderException("Protocol of service URL is not available."));
        } catch (URLBuilderException e) {
            e.printStackTrace();
        }
        IdentityResourceURLBuilder identityResourceURLBuilder = new IdentityResourceURLBuilder();
        identityResourceURLBuilder.setEndpointURIMap(DUMMY_ENDPOINT_URI_MAP);
        String buildValue = null;
        try {
            buildValue = identityResourceURLBuilder.build("resource3");
        } catch (NotFoundException e) {
            e.printStackTrace();
        }
        assertNull(buildValue);
    }

    @Test
    public void testBuildTenantQualifiedUrlsNotEnabled() throws NotFoundException {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(false);

        IdentityResourceURLBuilder identityResourceURLBuilder = new IdentityResourceURLBuilder();
        identityResourceURLBuilder.setEndpointURIMap(DUMMY_ENDPOINT_URI_MAP);
        String buildValue = identityResourceURLBuilder.build("resource");
        assertEquals(buildValue, "www.default.url");
    }

    @Test
    public void testBuildTenantQualifiedUrlsNotEnabledThrowNotFoundException() {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(false);

        IdentityResourceURLBuilder identityResourceURLBuilder = new IdentityResourceURLBuilder();
        identityResourceURLBuilder.setEndpointURIMap(DUMMY_ENDPOINT_URI_MAP);
        String buildValue = null;
        try {
            buildValue = identityResourceURLBuilder.build("resource3");
        } catch (NotFoundException e) {
            e.printStackTrace();
        }
        assertNull(buildValue);
    }
}
