/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.scim2.common.internal.action;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.Error;
import org.wso2.carbon.identity.action.execution.api.model.Failure;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.model.Organization;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutorService;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.util.ClaimConstants;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserAssociation;
import org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.model.MinimalOrganization;
import org.wso2.carbon.identity.scim2.common.internal.component.SCIMCommonComponentHolder;
import org.wso2.carbon.identity.user.action.api.constant.UserActionError;
import org.wso2.carbon.identity.user.action.api.exception.UserActionExecutionClientException;
import org.wso2.carbon.identity.user.action.api.exception.UserActionExecutionServerException;
import org.wso2.carbon.identity.user.action.api.model.UserActionContext;
import org.wso2.carbon.identity.user.action.api.model.UserActionRequestDTO;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.charon3.core.attributes.Attribute;
import org.wso2.charon3.core.attributes.SimpleAttribute;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.objects.User;

import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * This class triggers the execution of the pre update profile extension.
 * This executor should be invoked as user profile updates happen.
 */
public class PreUpdateProfileActionExecutor {

    private static final Log LOG = LogFactory.getLog(PreUpdateProfileActionExecutor.class);

    /**
     * Triggers the execution of pre update profile extension at profile update with PUT
     *
     * @param user                   SCIMUserObject reference that updates
     * @param userClaimsToBeModified Collection of new claims and existing claims that updates in the profile
     * @param userClaimsToBeDeleted  Collection of existing claims that deletes from the profile
     * @throws UserStoreException If an error occurs while executing the action
     */
    public void execute(User user, Map<String, String> userClaimsToBeModified,
                        Map<String, String> userClaimsToBeDeleted) throws UserStoreException {

        ActionExecutorService actionExecutorService = SCIMCommonComponentHolder.getActionExecutorService();

        if (!actionExecutorService.isExecutionEnabled(ActionType.PRE_UPDATE_PROFILE)) {
            return;
        }

        LOG.debug("Executing pre update profile action for user: " + user.getId());

        try {
            UserActionRequestDTO userActionRequestDTO =
                    buildUserActionRequestDTO(user, userClaimsToBeModified, userClaimsToBeDeleted);
            UserActionContext userActionContext = new UserActionContext(userActionRequestDTO);

            FlowContext flowContext = FlowContext.create();
            flowContext.add(UserActionContext.USER_ACTION_CONTEXT_REFERENCE_KEY, userActionContext);

            ActionExecutionStatus<?> actionExecutionStatus =
                    actionExecutorService.execute(ActionType.PRE_UPDATE_PROFILE, flowContext,
                            IdentityContext.getThreadLocalIdentityContext().getTenantDomain());

            handleActionExecutionStatus(actionExecutionStatus);
        } catch (ActionExecutionException e) {
            throw new UserActionExecutionServerException(UserActionError.PRE_UPDATE_PROFILE_ACTION_SERVER_ERROR,
                    "Error while executing pre update profile action.", e);
        }
    }

    private UserActionRequestDTO buildUserActionRequestDTO(User user, Map<String, String> userClaimsToBeModified,
                                                           Map<String, String> userClaimsToBeDeleted)
            throws UserStoreException {

        String managedOrgId = getUserManagedOrgId(user);
        UserActionRequestDTO.Builder userActionRequestDTOBuilder = new UserActionRequestDTO.Builder()
                .userId(getUserId(user, managedOrgId))
                .residentOrganization(getUserResidentOrganization(managedOrgId))
                .sharedUserId(managedOrgId != null ? user.getId(): null);

        populateUpdatingClaimsInUserActionRequestDTO(userClaimsToBeModified, userActionRequestDTOBuilder);
        populateDeletingClaimsInUserActionRequestDTO(userClaimsToBeDeleted, userActionRequestDTOBuilder);

        return userActionRequestDTOBuilder.build();
    }

    private void handleActionExecutionStatus(ActionExecutionStatus<?> actionExecutionStatus)
            throws UserStoreException {

        switch (actionExecutionStatus.getStatus()) {
            case SUCCESS:
                return;
            case FAILED:
                Failure failure = (Failure) actionExecutionStatus.getResponse();
                throw new UserActionExecutionClientException(UserActionError.PRE_UPDATE_PROFILE_ACTION_EXECUTION_FAILED,
                        failure.getFailureReason(), failure.getFailureDescription());
            case ERROR:
                Error error = (Error) actionExecutionStatus.getResponse();
                throw new UserActionExecutionServerException(UserActionError.PRE_UPDATE_PROFILE_ACTION_EXECUTION_ERROR,
                        error.getErrorMessage(), error.getErrorDescription());
            default:
                throw new UserActionExecutionServerException(UserActionError.PRE_UPDATE_PROFILE_ACTION_SERVER_ERROR,
                        "Unknown execution status received when executing pre update profile action.");
        }
    }

    private void populateDeletingClaimsInUserActionRequestDTO(Map<String, String> userClaimsToBeDeleted,
                                                              UserActionRequestDTO.Builder userActionRequestDTOBuilder)
            throws UserStoreException {

        for (Map.Entry<String, String> entry : userClaimsToBeDeleted.entrySet()) {
            String claimKey = entry.getKey();
            if (isMultiValuedClaim(claimKey)) {
                userActionRequestDTOBuilder.addClaim(claimKey, new String[]{});
            } else {
                userActionRequestDTOBuilder.addClaim(claimKey, "");
            }
        }
    }

    private void populateUpdatingClaimsInUserActionRequestDTO(Map<String, String> userClaims,
                                                              UserActionRequestDTO.Builder userActionRequestDTOBuilder)
            throws UserStoreException {

        String multiAttributeSeparator = FrameworkUtils.getMultiAttributeSeparator();
        for (Map.Entry<String, String> entry : userClaims.entrySet()) {
            String claimKey = entry.getKey();
            String claimValue = entry.getValue();
            if (isMultiValuedClaim(claimKey)) {
                userActionRequestDTOBuilder.addClaim(claimKey,
                        StringUtils.isBlank(claimValue) ? new String[]{} :
                                claimValue.split(Pattern.quote(multiAttributeSeparator)));
            } else {
                userActionRequestDTOBuilder.addClaim(claimKey, claimValue);
            }
        }
    }

    private boolean isMultiValuedClaim(String claimUri) throws UserStoreException {

        ClaimMetadataManagementService claimMetadataManagementService =
                SCIMCommonComponentHolder.getClaimManagementService();

        try {
            Optional<LocalClaim>
                    localClaim = claimMetadataManagementService.getLocalClaim(claimUri,
                    IdentityContext.getThreadLocalIdentityContext().getTenantDomain());

            if (!localClaim.isPresent()) {
                throw new UserActionExecutionServerException(UserActionError.PRE_UPDATE_PROFILE_ACTION_SERVER_ERROR,
                        "Claim not found for claim URI: " + claimUri);
            }

            return Boolean.parseBoolean(localClaim.get().getClaimProperty(ClaimConstants.MULTI_VALUED_PROPERTY));
        } catch (ClaimMetadataException e) {
            throw new UserActionExecutionServerException(UserActionError.PRE_UPDATE_PROFILE_ACTION_SERVER_ERROR,
                    "Error while retrieving claim metadata for claim URI: " + claimUri, e);
        }
    }

    private Organization getUserResidentOrganization(String managedOrgId) throws UserActionExecutionServerException {

        if (managedOrgId == null) {
            // User resident organization is the accessing organization if the managed organization claim is not set.
            org.wso2.carbon.identity.core.context.model.Organization accessingOrganization =
                    getOrganizationFromIdentityContext();

            return new Organization.Builder()
                    .id(accessingOrganization.getId())
                    .name(accessingOrganization.getName())
                    .orgHandle(accessingOrganization.getOrganizationHandle())
                    .depth(accessingOrganization.getDepth())
                    .build();
        }
        // If the managed organization claim is set, retrieve the organization details.
        return getOrganization(managedOrgId);
    }

    private org.wso2.carbon.identity.core.context.model.Organization getOrganizationFromIdentityContext()
            throws UserActionExecutionServerException {

        if (IdentityContext.getThreadLocalIdentityContext().getOrganization() == null) {
            throw new UserActionExecutionServerException(UserActionError.PRE_UPDATE_PROFILE_ACTION_SERVER_ERROR,
                    "Accessing organization is not present in the identity context.");
        }
        return IdentityContext.getThreadLocalIdentityContext().getOrganization();
    }

    private String getUserManagedOrgId(User user) throws UserActionExecutionServerException {

        try {
            Attribute systemSchemaAttribute = user.getAttribute("urn:scim:wso2:schema");
            if (systemSchemaAttribute == null) {
                return null;
            }
            Attribute managedOrgAttribute = systemSchemaAttribute.getSubAttribute("managedOrg");
            if (!(managedOrgAttribute instanceof SimpleAttribute)) {
                return null;
            }
            return String.valueOf(((SimpleAttribute) managedOrgAttribute).getValue());
        } catch (CharonException e) {
            throw new UserActionExecutionServerException(UserActionError.PRE_UPDATE_PROFILE_ACTION_SERVER_ERROR,
                    "Error while retrieving the user's managed by organization claim.", e);
        }
    }

    private Organization getOrganization(String managedOrgId) throws UserActionExecutionServerException {

        if (OrganizationManagementConstants.SUPER_ORG_ID.equals(managedOrgId)) {
            return new Organization.Builder()
                    .id(OrganizationManagementConstants.SUPER_ORG_ID)
                    .name(OrganizationManagementConstants.SUPER)
                    .orgHandle(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)
                    .depth(0)
                    .build();
        }

        try {
            MinimalOrganization minimalOrganization = SCIMCommonComponentHolder.getOrganizationManager()
                    .getMinimalOrganization(managedOrgId, null);
            if (minimalOrganization == null) {
                throw new UserActionExecutionServerException(UserActionError.PRE_UPDATE_PROFILE_ACTION_SERVER_ERROR,
                        "No organization found for the user's managed organization id: " + managedOrgId);
            }

            return new Organization.Builder()
                    .id(minimalOrganization.getId())
                    .name(minimalOrganization.getName())
                    .orgHandle(minimalOrganization.getOrganizationHandle())
                    .depth(minimalOrganization.getDepth())
                    .build();
        } catch (OrganizationManagementException e) {
            throw new UserActionExecutionServerException(UserActionError.PRE_UPDATE_PROFILE_ACTION_SERVER_ERROR,
                    "Error while retrieving organization details for the user's managed organization id: "
                            + managedOrgId, e);
        }
    }

    private String getUserId(User user, String managedOrgId) throws UserActionExecutionServerException {

        if (managedOrgId == null) {
            // User is not a shared user.
            return user.getId();
        }

        String accessingOrgId = getOrganizationFromIdentityContext().getId();
        try {
            UserAssociation userAssociation = SCIMCommonComponentHolder.getOrganizationUserSharingService()
                    .getUserAssociation(user.getId(), accessingOrgId);
            if (userAssociation == null) {
                throw new UserActionExecutionServerException(UserActionError.PRE_UPDATE_PROFILE_ACTION_SERVER_ERROR,
                        "No user association found for the user: " + user.getId() + " in organization: "
                                + accessingOrgId);
            }

            return userAssociation.getAssociatedUserId();
        } catch (OrganizationManagementException e) {
            throw new UserActionExecutionServerException(UserActionError.PRE_UPDATE_PROFILE_ACTION_SERVER_ERROR,
                    "Error while retrieving the shared user's association.", e);
        }
    }
}
