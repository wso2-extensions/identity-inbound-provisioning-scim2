/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.com).
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

package org.wso2.carbon.identity.scim2.common.listener;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.AbstractIdentityGroupDomainResolverListener;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.scim2.common.DAO.GroupDAO;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.Group;
import org.wso2.carbon.user.core.util.UserCoreUtil;

/**
 * Implementation of group domain resolver.
 */
public class SCIMGroupDomainResolverListener extends AbstractIdentityGroupDomainResolverListener {

    private static final Log diagnosticLog = LogFactory.getLog("diagnostics");
    private static final Log log = LogFactory.getLog(SCIMGroupDomainResolverListener.class);

    @Override
    public int getExecutionOrderId() {

        int orderId = super.getExecutionOrderId();
        if (orderId != IdentityCoreConstants.EVENT_LISTENER_ORDER_ID) {
            return orderId;
        }
        return 1;
    }

    @Override
    public boolean preResolveGroupDomainByGroupId(Group group, int tenantId)
            throws UserStoreException {

        if (group == null || StringUtils.isBlank(group.getGroupID())) {
            return true;
        }
        String groupId = group.getGroupID();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Retrieving group with id:%s from tenant: %s", groupId, tenantId));
        }
        diagnosticLog.info(String.format("Retrieving group with id: %s in tenant: %s", groupId, tenantId));
        GroupDAO groupDAO = new GroupDAO();
        String groupName;
        try {
            groupName = groupDAO.getGroupNameById(tenantId, groupId);
        } catch (IdentitySCIMException exception) {
            throw new UserStoreException(String.format("Error occurred while pre resolving the domain name for " +
                    "group: %s in tenant: %s", groupId, tenantId), exception);
        }
        if (StringUtils.isBlank(groupName)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No group found in IDN_SCIM_GROUP with group id: %s in tenant: %s", groupId,
                        tenantId));
            }
            return true;
        }
        String resolvedDomain = IdentityUtil.extractDomainFromName(groupName);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Domain: %s resolved for group id: %s in tenant: %s", resolvedDomain, groupId,
                    tenantId));
        }
        group.setGroupName(groupName);
        group.setDisplayName(UserCoreUtil.removeDomainFromName(groupName));
        group.setUserStoreDomain(resolvedDomain);
        return true;
    }
}
