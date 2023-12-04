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

package org.wso2.carbon.identity.scim2.common.listener;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.AbstractIdentityTenantMgtListener;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.Utils;
import org.wso2.carbon.identity.scim2.common.internal.SCIMCommonComponentHolder;
import org.wso2.carbon.identity.scim2.common.utils.AdminAttributeUtil;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.stratos.common.exception.StratosException;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Tenant activation listener for SCIM component to do the task when the tenant get create.
 *
 */
public class SCIMTenantMgtListener extends AbstractIdentityTenantMgtListener {

    private static final Log log = LogFactory.getLog(SCIMTenantMgtListener.class);
    @Override
    public void onTenantInitialActivation(int tenantId) throws StratosException {

        boolean isEnabled = isEnable();
        if (!isEnabled) {
            if (log.isDebugEnabled()) {
                log.debug("SCIMTenantMgtListener is disabled");
            }
            return;
        }
        RealmService realmService = SCIMCommonComponentHolder.getRealmService();
        try {
            Tenant tenant = realmService.getTenantManager().getTenant(tenantId);
            /*
            If the tenant has an associated organization id, and if the org id satisfies isOrganization() check, that
            organization creator is not inside the same organization. No need to update such admin claims.
             */
            String organizationID = tenant.getAssociatedOrganizationUUID();
            if (StringUtils.isNotBlank(organizationID)) {
                OrganizationManager organizationManager = SCIMCommonComponentHolder.getOrganizationManager();
                int organizationDepth = organizationManager.getOrganizationDepthInHierarchy(organizationID);
                if (organizationDepth >= Utils.getSubOrgStartLevel()) {
                    return;
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("SCIMTenantMgtListener is fired for Tenant ID : " + tenantId);
            }
            // Update admin user attributes.
            AdminAttributeUtil.updateAdminUser(tenantId, false);
            // Update admin group attributes.
            AdminAttributeUtil.updateAdminGroup(tenantId);
            // Update meta data of everyone role.
            SCIMCommonUtils.updateEveryOneRoleV2MetaData(tenantId);
        } catch (UserStoreException | OrganizationManagementException e) {
            log.error(e);
        }
    }
}
