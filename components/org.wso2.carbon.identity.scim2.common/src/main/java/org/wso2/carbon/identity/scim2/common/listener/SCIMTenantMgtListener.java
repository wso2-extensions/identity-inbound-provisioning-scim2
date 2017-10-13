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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.AbstractIdentityTenantMgtListener;
import org.wso2.carbon.identity.scim2.common.utils.AdminAttributeUtil;
import org.wso2.carbon.stratos.common.exception.StratosException;

/**
 * Tenant activation listener for SCIM component to do the task when the tenant get create.
 *
 */
public class SCIMTenantMgtListener extends AbstractIdentityTenantMgtListener {

    private static Log log = LogFactory.getLog(SCIMTenantMgtListener.class);
    @Override
    public void onTenantInitialActivation(int tenantId) throws StratosException {

        if (log.isDebugEnabled()) {
            log.debug("SCIMTenantMgtListener is fired for Tenant ID : " + tenantId);
        }
        //Update admin user attributes.
        AdminAttributeUtil.updateAdminUser(tenantId, false);
        //Update admin group attributes.
        AdminAttributeUtil.updateAdminGroup(tenantId);
    }
}
