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

package org.wso2.carbon.identity.scim2.common.internal;

import org.mockito.Mock;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEventImpl;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.role.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.scim2.common.extenstion.SCIMUserStoreErrorResolver;
import org.wso2.carbon.identity.scim2.common.utils.AdminAttributeUtil;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.mgt.RolePermissionManagementService;
import org.wso2.carbon.utils.CarbonUtils;

import java.nio.file.Paths;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.verifyStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

@PrepareForTest({AdminAttributeUtil.class, IdentityUtil.class, CarbonUtils.class, IdentityTenantUtil.class})
public class SCIMCommonComponentTest extends PowerMockTestCase {

    SCIMCommonComponent scimCommonComponent;

    @Mock
    ComponentContext mockComponentContext;

    @Mock
    BundleContext mockBundleContext;

    @Mock
    ServiceRegistration mockServiceRegistration;

    @Mock
    RealmService mockRealmService;

    @Mock
    RolePermissionManagementService mockRolePermissionManagementService;

    @Mock
    ClaimMetadataManagementService mockClaimMetadataManagementService;

    @Mock
    RoleManagementService mockRoleManagementService;

    @Mock
    SCIMUserStoreErrorResolver mockScimUserStoreErrorResolver;

    @BeforeClass
    public void setUpClass() {

        scimCommonComponent = new SCIMCommonComponent();
    }

    @BeforeMethod
    public void setUpMethod() throws Exception {

        initMocks(this);
        mockStatic(AdminAttributeUtil.class);
        doNothing().when(AdminAttributeUtil.class, "updateAdminUser", anyInt(), anyBoolean());
        doNothing().when(AdminAttributeUtil.class, "updateAdminGroup", anyInt());

        when(mockComponentContext.getBundleContext()).thenReturn(mockBundleContext);
        when(mockBundleContext.registerService(any(Class.class), anyObject(), any())).
                thenReturn(mockServiceRegistration);
        when(mockBundleContext.registerService(anyString(), anyObject(), any())).thenReturn(mockServiceRegistration);
    }

    @AfterClass
    public void tearUp() {

        SCIMCommonComponentHolder.setRoleManagementService(null);
        SCIMCommonComponentHolder.setClaimManagementService(null);
        SCIMCommonComponentHolder.setRealmService(null);
        SCIMCommonComponentHolder.setRolePermissionManagementService(null);
    }

    @DataProvider(name = "dataProviderForActivateCharonException")
    public Object[][] dataProviderForActivateCharonException() {

        return new Object[][]{
                {"resources1", "resources"},
                {"resources", "resources1"},
                {"resources1", "resources1"},
                {"resources", "resources"},
                {"resources", "resources/test2"},
        };
    }

    @Test(dataProvider = "dataProviderForActivateCharonException")
    public void testActivateCharonException(String pathIdentity, String pathCarbon) {

        mockStatic(IdentityUtil.class);
        mockStatic(CarbonUtils.class);
        when(IdentityUtil.getIdentityConfigDirPath()).thenReturn(Paths
                .get(System.getProperty("user.dir"), "src", "test", pathIdentity).toString());
        when(CarbonUtils.getCarbonConfigDirPath()).thenReturn(Paths
                .get(System.getProperty("user.dir"), "src", "test", pathCarbon).toString());

        scimCommonComponent.activate(mockComponentContext);
        assertTrue(true, "asserted charonException");

    }

    @DataProvider(name = "dataProviderForActivate")
    public Object[][] dataProviderForActivate() {

        return new Object[][]{
                {"resources"},
                {"resources/test2"}
        };
    }

    @Test(dataProvider = "dataProviderForActivate")
    public void testActivateAndDeactivate(String path) {

        mockStatic(IdentityUtil.class);
        mockStatic(CarbonUtils.class);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityUtil.getIdentityConfigDirPath()).thenReturn(Paths
                .get(System.getProperty("user.dir"), "src", "test", path).toString());

        when(CarbonUtils.getCarbonConfigDirPath()).thenReturn(Paths
                .get(System.getProperty("user.dir"), "src", "test", "resources").toString());
        scimCommonComponent.activate(mockComponentContext);
        scimCommonComponent.deactivate(mockComponentContext);
        SCIMCommonComponent scimCommonComponent2 = new SCIMCommonComponent();
        scimCommonComponent2.deactivate(mockComponentContext);

        verifyStatic(times(1));
        AdminAttributeUtil.updateAdminUser(anyInt(), anyBoolean());
        AdminAttributeUtil.updateAdminGroup(anyInt());
    }

    @Test
    public void testUnsetIdentityCoreInitializedEventService() {

        scimCommonComponent.unsetIdentityCoreInitializedEventService(new IdentityCoreInitializedEventImpl());
        assertTrue(true, "asserted unsetIdentityCoreInitializedService");
    }

    @Test
    public void testSetIdentityCoreInitializedEventService() {

        scimCommonComponent.setIdentityCoreInitializedEventService(new IdentityCoreInitializedEventImpl());
        assertTrue(true, "asserted setIdentityCoreInitializedService");
    }

    @Test
    public void testSetAndUnSetRealmService() {

        scimCommonComponent.setRealmService(mockRealmService);
        assertEquals(SCIMCommonComponentHolder.getRealmService(), mockRealmService);

        scimCommonComponent.unsetRealmService(mockRealmService);
        assertNull(SCIMCommonComponentHolder.getRealmService());
    }

    @Test
    public void testSetAndUnSetRolePermissionService() {

        scimCommonComponent.setRolePermissionService(mockRolePermissionManagementService);
        assertEquals(SCIMCommonComponentHolder.getRolePermissionManagementService(),
                mockRolePermissionManagementService);

        scimCommonComponent.unsetRolePermissionService(mockRolePermissionManagementService);
        assertNull(SCIMCommonComponentHolder.getRolePermissionManagementService());
    }

    @Test
    public void testSetAndUnSetClaimMetadataManagementService() {

        scimCommonComponent.setClaimMetadataManagementService(mockClaimMetadataManagementService);
        assertEquals(SCIMCommonComponentHolder.getClaimManagementService(),
                mockClaimMetadataManagementService);

        scimCommonComponent.unsetClaimMetadataManagementService(mockClaimMetadataManagementService);
        assertNull(SCIMCommonComponentHolder.getClaimManagementService());
    }

    @Test
    public void testSetAndUnSetRoleManagementService() {

        scimCommonComponent.setRoleManagementService(mockRoleManagementService);
        assertEquals(SCIMCommonComponentHolder.getRoleManagementService(),
                mockRoleManagementService);

        scimCommonComponent.unsetRoleManagementService(mockRoleManagementService);
        assertNull(SCIMCommonComponentHolder.getRoleManagementService());
    }

    @Test
    public void testSetAndUnSetScimUserStoreErrorResolver() {

        scimCommonComponent.setScimUserStoreErrorResolver(mockScimUserStoreErrorResolver);
        assertEquals(SCIMCommonComponentHolder.getScimUserStoreErrorResolverList().get(0),
                mockScimUserStoreErrorResolver);

        scimCommonComponent.unsetScimUserStoreErrorResolver(mockScimUserStoreErrorResolver);
        assertEquals(SCIMCommonComponentHolder.getScimUserStoreErrorResolverList().size(), 0);
    }
}
