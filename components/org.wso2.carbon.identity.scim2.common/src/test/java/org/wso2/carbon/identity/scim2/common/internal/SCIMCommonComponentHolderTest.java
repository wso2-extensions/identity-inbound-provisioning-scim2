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
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.AfterClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.role.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.scim2.common.extenstion.SCIMUserStoreErrorResolver;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.mgt.RolePermissionManagementService;

import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class SCIMCommonComponentHolderTest extends PowerMockTestCase {

    @AfterClass
    public void tearUp() {

        SCIMCommonComponentHolder.setRoleManagementService(null);
        SCIMCommonComponentHolder.setClaimManagementService(null);
        SCIMCommonComponentHolder.setRealmService(null);
        SCIMCommonComponentHolder.setRolePermissionManagementService(null);
    }

    @Mock
    RealmService mockRealmService;

    @Mock
    RolePermissionManagementService mockRolePermissionManagementService;

    @Mock
    ClaimMetadataManagementService mockClaimMetadataManagementService;

    @Mock
    RoleManagementService mockRoleManagementService;

    @Mock
    SCIMUserStoreErrorResolver mockScimUserStoreErrorResolver1;

    @Mock
    SCIMUserStoreErrorResolver mockScimUserStoreErrorResolver2;

    @Test
    public void testGetAndSetRealmService() {

        assertNull(SCIMCommonComponentHolder.getRealmService());
        SCIMCommonComponentHolder.setRealmService(mockRealmService);
        RealmService realmService = SCIMCommonComponentHolder.getRealmService();
        assertEquals(realmService, mockRealmService);
    }

    @Test
    public void testGetAndSetRolePermissionManagementService() {

        assertNull(SCIMCommonComponentHolder.getRolePermissionManagementService());
        SCIMCommonComponentHolder.setRolePermissionManagementService(mockRolePermissionManagementService);
        RolePermissionManagementService rolePermissionManagementService = SCIMCommonComponentHolder.
                getRolePermissionManagementService();
        assertEquals(rolePermissionManagementService, mockRolePermissionManagementService);
    }

    @Test
    public void testGetAndSetClaimManagementService() {

        assertNull(SCIMCommonComponentHolder.getClaimManagementService());
        SCIMCommonComponentHolder.setClaimManagementService(mockClaimMetadataManagementService);
        ClaimMetadataManagementService claimMetadataManagementService = SCIMCommonComponentHolder.
                getClaimManagementService();
        assertEquals(claimMetadataManagementService, mockClaimMetadataManagementService);
    }

    @Test
    public void testGetAndSetRoleManagementService() {

        assertNull(SCIMCommonComponentHolder.getRoleManagementService());
        SCIMCommonComponentHolder.setRoleManagementService(mockRoleManagementService);
        RoleManagementService roleManagementService = SCIMCommonComponentHolder.getRoleManagementService();
        assertEquals(roleManagementService, mockRoleManagementService);
    }

    @Test
    public void testAddANdGetAndRemoveScimUserStoreErrorResolverList() {

        assertTrue(SCIMCommonComponentHolder.getScimUserStoreErrorResolverList().isEmpty(), "empty list");
        SCIMCommonComponentHolder.addScimUserStoreErrorResolver(mockScimUserStoreErrorResolver1);
        SCIMCommonComponentHolder.addScimUserStoreErrorResolver(mockScimUserStoreErrorResolver2);
        List<SCIMUserStoreErrorResolver> scimUserStoreErrorResolvers = SCIMCommonComponentHolder.
                getScimUserStoreErrorResolverList();
        assertEquals(scimUserStoreErrorResolvers.get(0), mockScimUserStoreErrorResolver1);
        assertEquals(scimUserStoreErrorResolvers.get(1), mockScimUserStoreErrorResolver2);
        SCIMCommonComponentHolder.removeScimUserStoreErrorResolver(mockScimUserStoreErrorResolver1);
        assertEquals(scimUserStoreErrorResolvers.get(0), mockScimUserStoreErrorResolver2);
        SCIMCommonComponentHolder.removeScimUserStoreErrorResolver(mockScimUserStoreErrorResolver2);
        assertTrue(SCIMCommonComponentHolder.getScimUserStoreErrorResolverList().isEmpty(), "empty list");
    }
}