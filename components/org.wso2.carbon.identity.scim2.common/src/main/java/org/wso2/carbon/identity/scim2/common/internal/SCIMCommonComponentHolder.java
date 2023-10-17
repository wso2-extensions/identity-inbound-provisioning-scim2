/*
 * Copyright (c) 2017-2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.scim2.common.extenstion.SCIMUserStoreErrorResolver;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.mgt.RolePermissionManagementService;
import org.wso2.carbon.identity.role.mgt.core.RoleManagementService;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * SCIM service holder class.
 *
 */
public class SCIMCommonComponentHolder {

    private static RealmService realmService;
    private static ClaimMetadataManagementService claimManagementService;
    private static RolePermissionManagementService rolePermissionManagementService;
    private static RoleManagementService roleManagementService;
    private static org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService roleManagementServiceV2;
    private static final List<SCIMUserStoreErrorResolver> scimUserStoreErrorResolvers = new ArrayList<>();

    /**
     * Get realm service.
     *
     * @return
     */
    public static RealmService getRealmService() {

        return SCIMCommonComponentHolder.realmService;
    }

    /**
     * Set realm service.
     *
     * @param realmService
     */
    public static void setRealmService(RealmService realmService) {

        SCIMCommonComponentHolder.realmService = realmService;
    }

    /**
     * Get role permission management service.
     *
     * @return
     */
    public static RolePermissionManagementService getRolePermissionManagementService() {

        return rolePermissionManagementService;
    }

    /**
     * Set role permission management service.
     *
     * @param rolePermissionManagementService
     */
    public static void setRolePermissionManagementService(RolePermissionManagementService
                                                                  rolePermissionManagementService) {

        SCIMCommonComponentHolder.rolePermissionManagementService = rolePermissionManagementService;
    }

    /**
     * Get claim metadata management service.
     * @return
     */
    public static ClaimMetadataManagementService getClaimManagementService() {

        return claimManagementService;
    }

    /**
     * Set claim metadata management service.
     *
     * @param claimManagementService
     */
    public static void setClaimManagementService(ClaimMetadataManagementService claimManagementService) {

        SCIMCommonComponentHolder.claimManagementService = claimManagementService;
    }

    /**
     * Set role management service.
     *
     * @param roleManagementService RoleManagementService.
     */
    public static void setRoleManagementService(RoleManagementService roleManagementService) {

        SCIMCommonComponentHolder.roleManagementService = roleManagementService;
    }

    /**
     * Get role management service.
     *
     * @return RoleManagementService.
     */
    public static RoleManagementService getRoleManagementService() {

        return roleManagementService;
    }

    /**
     * Set role management service V2.
     *
     * @param roleManagementService RoleManagementServiceV2.
     */
    public static void setRoleManagementServiceV2(
            org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService roleManagementService) {

        SCIMCommonComponentHolder.roleManagementServiceV2 = roleManagementService;
    }

    /**
     * Get role management service V2.
     *
     * @return RoleManagementServiceV2.
     */
    public static org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService getRoleManagementServiceV2() {

        return roleManagementServiceV2;
    }

    public static List<SCIMUserStoreErrorResolver> getScimUserStoreErrorResolverList() {

        return scimUserStoreErrorResolvers;
    }

    public static void addScimUserStoreErrorResolver(SCIMUserStoreErrorResolver scimUserStoreErrorResolver) {

        scimUserStoreErrorResolvers.add(scimUserStoreErrorResolver);
        scimUserStoreErrorResolvers.sort(Comparator.comparing(SCIMUserStoreErrorResolver::getOrder).reversed());
    }

    public static void removeScimUserStoreErrorResolver(SCIMUserStoreErrorResolver scimUserStoreErrorResolver) {

        scimUserStoreErrorResolvers.remove(scimUserStoreErrorResolver);
        scimUserStoreErrorResolvers.sort(Comparator.comparing(SCIMUserStoreErrorResolver::getOrder).reversed());
    }
}
