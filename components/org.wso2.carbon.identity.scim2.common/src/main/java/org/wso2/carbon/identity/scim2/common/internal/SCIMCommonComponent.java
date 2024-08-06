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
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.role.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.scim2.common.extenstion.SCIMUserStoreErrorResolver;
import org.wso2.carbon.identity.scim2.common.handlers.SCIMClaimOperationEventHandler;
import org.wso2.carbon.identity.scim2.common.impl.DefaultSCIMUserStoreErrorResolver;
import org.wso2.carbon.identity.scim2.common.listener.SCIMGroupResolver;
import org.wso2.carbon.identity.scim2.common.listener.SCIMTenantMgtListener;
import org.wso2.carbon.identity.scim2.common.listener.SCIMUserOperationListener;
import org.wso2.carbon.identity.scim2.common.utils.AdminAttributeUtil;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.identity.scim2.common.utils.SCIMConfigProcessor;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;
import org.wso2.carbon.user.core.listener.GroupResolver;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.mgt.RolePermissionManagementService;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.charon3.core.config.SCIMConfigConstants;
import org.wso2.charon3.core.config.SCIMCustomSchemaExtensionBuilder;
import org.wso2.charon3.core.config.SCIMUserSchemaExtensionBuilder;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.InternalErrorException;
import org.wso2.carbon.idp.mgt.IdpManager;

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
            // If custom schema is enabled, read it root attribute URI from the file config if it is configured.
            if (SCIMCommonUtils.isCustomSchemaEnabled()) {
                SCIMCustomSchemaExtensionBuilder.getInstance().setURI(SCIMCommonUtils.getCustomSchemaURI());
            }

            //register UserOperationEventListener implementation
            SCIMUserOperationListener scimUserOperationListener = new SCIMUserOperationListener();
            userOperationEventListenerServiceReg = ctx.getBundleContext()
                    .registerService(UserOperationEventListener.class, scimUserOperationListener, null);

            //register scimTenantMgtListener implementation
            SCIMTenantMgtListener scimTenantMgtListener = new SCIMTenantMgtListener();
            tenantMgtListenerServiceReg = ctx.getBundleContext().registerService(TenantMgtListener.class,
                    scimTenantMgtListener, null);

            // Register claim operation event handler implementation.
            ctx.getBundleContext().registerService(AbstractEventHandler.class.getName(),
                    new SCIMClaimOperationEventHandler(), null);
            if (logger.isDebugEnabled()) {
                logger.debug("SCIMClaimOperationEventHandler is successfully registered.");
            }

            // Register default implementation of SCIMUserStoreErrorResolver
            ctx.getBundleContext().registerService(SCIMUserStoreErrorResolver.class.getName(),
                    new DefaultSCIMUserStoreErrorResolver(), null);

            // Register default implementation of SCIMGroupResolver.
            ctx.getBundleContext().registerService(GroupResolver.class.getName(),
                    new SCIMGroupResolver(), null);

            //Update super tenant user/group attributes.
            AdminAttributeUtil.updateAdminUser(MultitenantConstants.SUPER_TENANT_ID, true);
            AdminAttributeUtil.updateAdminGroup(MultitenantConstants.SUPER_TENANT_ID);
            SCIMCommonUtils.updateEveryOneRoleV2MetaData(MultitenantConstants.SUPER_TENANT_ID);
            SCIMCommonUtils.updateSystemRoleV2MetaData(MultitenantConstants.SUPER_TENANT_ID);
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
            service = org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService.class,
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

    /**
     * Set role management service implementation.
     *
     * @param roleManagementService RoleManagementService
     */
    @Reference(
            name = "org.wso2.carbon.identity.role.mgt.core.RoleManagementService",
            service = org.wso2.carbon.identity.role.mgt.core.RoleManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRoleManagementService")
    protected void setRoleManagementService(RoleManagementService roleManagementService) {

        if (logger.isDebugEnabled()) {
            logger.debug("RoleManagementService set in SCIMCommonComponent bundle.");
        }
        SCIMCommonComponentHolder.setRoleManagementService(roleManagementService);
    }

    /**
     * Unset role management service implementation.
     */
    protected void unsetRoleManagementService(RoleManagementService roleManagementService) {

        if (logger.isDebugEnabled()) {
            logger.debug("RoleManagementService unset in SCIMCommonComponent bundle.");
        }
        SCIMCommonComponentHolder.setRoleManagementService(null);
    }

    /**
     * Set role management service V2 implementation.
     *
     * @param roleManagementService RoleManagementServiceV2.
     */
    @Reference(
            name = "org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService",
            service = org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRoleManagementServiceV2")
    protected void setRoleManagementServiceV2(org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService roleManagementService) {

        SCIMCommonComponentHolder.setRoleManagementServiceV2(roleManagementService);
        logger.debug("RoleManagementServiceV2 set in SCIMCommonComponent bundle.");
    }

    /**
     * Unset role management service V2 implementation.
     *
     * @param roleManagementService RoleManagementServiceV2
     */
    protected void unsetRoleManagementServiceV2(org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService roleManagementService) {

        SCIMCommonComponentHolder.setRoleManagementServiceV2(null);
        logger.debug("RoleManagementServiceV2 unset in SCIMCommonComponent bundle.");
    }

    /**
     * Set idp manager service implementation.
     *
     * @param idpManager Idp manager service.
     */
    @Reference(
            name = "org.wso2.carbon.idp.mgt.IdpManager",
            service = org.wso2.carbon.idp.mgt.IdpManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdPManagerService")
    protected void setIdPManagerService(IdpManager idpManager) {

        SCIMCommonComponentHolder.setIdpManagerService(idpManager);
        logger.debug("IdPManagerService set in SCIMCommonComponent bundle.");
    }

    /**
     * Unset idp manager service implementation.
     *
     * @param idpManager Idp manager service.
     */
    protected void unsetIdPManagerService(IdpManager idpManager) {

        SCIMCommonComponentHolder.setIdpManagerService(null);
        logger.debug("IdPManagerService unset in SCIMCommonComponent bundle.");
    }

    /**
     * Set SCIMUserStoreErrorResolver implementation
     *
     * @param scimUserStoreErrorResolver SCIMUserStoreErrorResolver
     */
    @Reference(
            name = "scim.user.store.error.resolver",
            service = org.wso2.carbon.identity.scim2.common.extenstion.SCIMUserStoreErrorResolver.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetScimUserStoreErrorResolver")
    protected void setScimUserStoreErrorResolver(SCIMUserStoreErrorResolver scimUserStoreErrorResolver) {

        SCIMCommonComponentHolder.addScimUserStoreErrorResolver(scimUserStoreErrorResolver);
    }

    protected void unsetScimUserStoreErrorResolver(SCIMUserStoreErrorResolver scimUserStoreErrorResolver) {

        SCIMCommonComponentHolder.removeScimUserStoreErrorResolver(scimUserStoreErrorResolver);
    }

    @Reference(name = "identity.organization.management.component",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager")
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        SCIMCommonComponentHolder.setOrganizationManager(organizationManager);
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        SCIMCommonComponentHolder.setOrganizationManager(null);
    }

    /**
     * Unset identityEventService service implementation.
     *
     * @param identityEventService IdentityEventService
     */
    protected void unsetIdentityEventService(IdentityEventService identityEventService) {

        SCIMCommonComponentHolder.setIdentityEventService(null);
    }

    /**
     * Set IdentityEventService implementation
     *
     * @param identityEventService IdentityEventService
     */
    @Reference(
            name = "IdentityEventService",
            service = org.wso2.carbon.identity.event.services.IdentityEventService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityEventService")
    protected void setIdentityEventService(IdentityEventService identityEventService) {

        SCIMCommonComponentHolder.setIdentityEventService(identityEventService);
    }

    @Reference(
            name = "resource.configuration.manager",
            service = ConfigurationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetConfigurationManager"
    )

    /**
     * This method is used to set the Configuration manager Service.
     *
     * @param configurationManager The Realm Service which needs to be set.
     */
    protected void setConfigurationManager(ConfigurationManager configurationManager) {

        SCIMCommonComponentHolder.setConfigurationManager(configurationManager);
    }

    /**
     * This method is used to unset the Configuration manager Service.
     *
     * @param configurationManager The Configuration manager Service which needs to unset.
     */
    protected void unsetConfigurationManager(ConfigurationManager configurationManager) {

        SCIMCommonComponentHolder.setConfigurationManager(null);
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
