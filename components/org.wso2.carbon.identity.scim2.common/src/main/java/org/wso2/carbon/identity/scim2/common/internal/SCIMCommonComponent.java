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

package org.wso2.carbon.identity.scim2.common.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.scim2.common.listener.SCIMTenantMgtListener;
import org.wso2.carbon.identity.scim2.common.listener.SCIMUserOperationListener;
import org.wso2.carbon.identity.scim2.common.utils.AdminAttributeUtil;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.scim2.common.utils.SCIMConfigProcessor;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.mgt.RolePermissionManagementService;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.charon3.core.config.SCIMConfigConstants;
import org.wso2.charon3.core.config.SCIMUserSchemaExtensionBuilder;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.InternalErrorException;

import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Component(
        name = "identity.scim2.common",
        immediate = true
)
public class SCIMCommonComponent {

    private static final Log logger = LogFactory.getLog(SCIMCommonComponent.class);

    ExecutorService executorService = Executors.newFixedThreadPool(1);

    private ServiceRegistration<TenantMgtListener> tenantMgtListenerServiceReg;
    private ServiceRegistration<UserOperationEventListener> userOperationEventListenerServiceReg;

    @Activate
    protected void activate(ComponentContext ctx) {

        try {
            String filePath = IdentityUtil.getIdentityConfigDirPath() + File.separator +
                    SCIMCommonConstants.CHARON_CONFIG_NAME;

            SCIMConfigProcessor scimConfigProcessor = SCIMConfigProcessor.getInstance();
            scimConfigProcessor.buildConfigFromFile(filePath);

            // reading user schema extension
            if (Boolean.parseBoolean(scimConfigProcessor.getProperty("user-schema-extension-enabled"))) {
                String schemaFilePath =
                        CarbonUtils.getCarbonConfigDirPath() + File.separator +
                                SCIMConfigConstants.SCIM_SCHEMA_EXTENSION_CONFIG;
                SCIMUserSchemaExtensionBuilder.getInstance().buildUserSchemaExtension(schemaFilePath);
            }

            //register UserOperationEventListener implementation
            SCIMUserOperationListener scimUserOperationListener = new SCIMUserOperationListener();
            userOperationEventListenerServiceReg = ctx.getBundleContext()
                    .registerService(UserOperationEventListener.class, scimUserOperationListener, null);

            //register scimTenantMgtListener implementation
            SCIMTenantMgtListener scimTenantMgtListener = new SCIMTenantMgtListener();
            tenantMgtListenerServiceReg = ctx.getBundleContext().registerService(TenantMgtListener.class,
                    scimTenantMgtListener, null);

            //Update super tenant user/group attributes.
            AdminAttributeUtil.updateAdminUser(MultitenantConstants.SUPER_TENANT_ID, true);
            AdminAttributeUtil.updateAdminGroup(MultitenantConstants.SUPER_TENANT_ID);

            if (logger.isDebugEnabled()) {
                logger.debug("SCIM Common component activated successfully.");
            }
        } catch (CharonException e) {
            logger.error("Error in reading information from identity tables at SCIMCommonComponentStartup.", e);
        } catch (InternalErrorException e) {
            logger.error("Error in reading information from identity tables at SCIMCommonComponentStartup.", e);
        }
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    @Reference(
            name = "identityCoreInitializedEventService",
            service = org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent.class,
            policy = ReferencePolicy.DYNAMIC,
            cardinality = ReferenceCardinality.MANDATORY,
            unbind = "unsetIdentityCoreInitializedEventService"
    )
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    /**
     * Set realm service implementation
     *
     * @param realmService RealmService
     */
    @Reference(
            name = "user.realmservice.default",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (logger.isDebugEnabled()) {
            logger.debug("realmService set in SCIMCommonComponent bundle");
        }
        SCIMCommonComponentHolder.setRealmService(realmService);
    }

    /**
     * Unset realm service implementation
     */
    protected void unsetRealmService(RealmService realmService) {

        if (logger.isDebugEnabled()) {
            logger.debug("realmService unset in SCIMCommonComponent bundle");
        }
        SCIMCommonComponentHolder.setRealmService(null);
    }

    @Reference(
            name = "role.permission.management.service",
            service = org.wso2.carbon.user.mgt.RolePermissionManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRolePermissionService")
    protected void setRolePermissionService(RolePermissionManagementService rolePermissionService) {

        if (logger.isDebugEnabled()) {
            logger.debug("RolePermissionManagementService is set in SCIMCommonComponent bundle.");
        }
        SCIMCommonComponentHolder.setRolePermissionManagementService(rolePermissionService);
    }

    /**
     * Unset role permission management service implementation.
     */
    protected void unsetRolePermissionService(RolePermissionManagementService rolePermissionService) {

        if (logger.isDebugEnabled()) {
            logger.debug("RolePermissionManagementService unset in SCIMCommonComponent bundle.");
        }
        SCIMCommonComponentHolder.setRolePermissionManagementService(null);
    }

    /**
     * Set claim metadata management service implementation.
     *
     * @param claimManagementService ClaimManagementService
     */
    @Reference(
            name = "claimManagementService",
            service = org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService .class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetClaimMetadataManagementService")
    protected void setClaimMetadataManagementService(ClaimMetadataManagementService claimManagementService) {

        if (logger.isDebugEnabled()) {
            logger.debug("claimManagementService set in SCIMCommonComponent bundle");
        }
        SCIMCommonComponentHolder.setClaimManagementService(claimManagementService);
    }

    /**
     * Unset claim metadata management service implementation.
     */
    protected void unsetClaimMetadataManagementService(ClaimMetadataManagementService claimManagementService) {

        if (logger.isDebugEnabled()) {
            logger.debug("claimManagementService unset in SCIMCommonComponent bundle");
        }
        SCIMCommonComponentHolder.setClaimManagementService(null);
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (tenantMgtListenerServiceReg != null) {
            tenantMgtListenerServiceReg.unregister();
        }

        if (userOperationEventListenerServiceReg != null) {
            userOperationEventListenerServiceReg.unregister();
        }
    }
}
