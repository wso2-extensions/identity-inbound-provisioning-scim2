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

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.UserCoreConstants;

import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;


@PrepareForTest({IdentityUtil.class})
public class SCIMCommonUtilsTest extends PowerMockTestCase {

    private static final String ID = "8a439cf6-3c6b-47d2-94bf-34d072495af3";
    private static final String SCIM_URL = "https://localhost:9443/scim2";
    private String scimUserLocation = SCIM_URL + SCIMCommonConstants.USERS;
    private String scimGroupLocation = SCIM_URL + SCIMCommonConstants.GROUPS;
    private String scimServiceProviderConfig = SCIM_URL + SCIMCommonConstants.SERVICE_PROVIDER_CONFIG;
    private String scimResourceType = SCIM_URL + SCIMCommonConstants.RESOURCE_TYPE;

    @BeforeMethod
    public void setUp() throws Exception {
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).thenReturn(SCIM_URL);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    @Test
    public void testGetSCIMUserURL() throws Exception {
        String scimUserURL = SCIMCommonUtils.getSCIMUserURL(ID);
        Assert.assertEquals(scimUserURL, scimUserLocation + "/" + ID);
    }

    @Test
    public void testGetSCIMGroupURL() throws Exception {
        String scimGroupURL = SCIMCommonUtils.getSCIMGroupURL(ID);
        Assert.assertEquals(scimGroupURL, scimGroupLocation + "/" + ID);
    }

    @Test
    public void testGetSCIMServiceProviderConfigURL() throws Exception {
        String scimServiceProviderConfigURL = SCIMCommonUtils.getSCIMServiceProviderConfigURL(ID);
        Assert.assertEquals(scimServiceProviderConfigURL, scimServiceProviderConfig);
    }

    @Test
    public void testGetSCIMUserURL1() throws Exception {
        String scimUsersURL = SCIMCommonUtils.getSCIMUserURL();
        Assert.assertEquals(scimUsersURL, scimUserLocation);
    }

    @Test
    public void testGetSCIMGroupURL1() throws Exception {
        String scimGroupsURL = SCIMCommonUtils.getSCIMGroupURL();
        Assert.assertEquals(scimGroupsURL, scimGroupLocation);
    }

    @Test
    public void testGetSCIMServiceProviderConfigURL1() throws Exception {
        String scimServiceProviderConfigURL = SCIMCommonUtils.getSCIMServiceProviderConfigURL();
        Assert.assertEquals(scimServiceProviderConfigURL, scimServiceProviderConfig);
    }

    @Test
    public void testGetSCIMResourceTypeURL() throws Exception {
        String scimResourceTypeURL = SCIMCommonUtils.getSCIMResourceTypeURL();
        Assert.assertEquals(scimResourceTypeURL, scimResourceType);
    }

    @DataProvider(name = "groupNames")
    public Object[][] getGroupNames() {

        return new Object[][]{
                {null, null},
                {"TESTDOMAIN/testGroup", "TESTDOMAIN/testGroup"},
                {"testGroup", UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME + CarbonConstants.DOMAIN_SEPARATOR + "testGroup"}
        };
    }

    @Test(dataProvider = "groupNames")
    public void testGetGroupNameWithDomain(String paramValue, String expectedResult) throws Exception {
        Assert.assertEquals(SCIMCommonUtils.getGroupNameWithDomain(paramValue), expectedResult);
    }

    @DataProvider(name = "groupNamesWithDomain")
    public Object[][] getGroupNamesWithDomain() {

        return new Object[][]{
                {null, null},
                {"TESTDOMAIN/testGroup", "TESTDOMAIN/testGroup"},
                {UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME + "/testGroup", "testGroup"},
                {"testGroup", "testGroup"}
        };
    }

    @Test(dataProvider = "groupNamesWithDomain")
    public void testGetPrimaryFreeGroupName(String groupName, String expectedResult) throws Exception {
        Assert.assertEquals(SCIMCommonUtils.getPrimaryFreeGroupName(groupName), expectedResult);
    }

}
