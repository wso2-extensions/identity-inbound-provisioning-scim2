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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.Error;
import org.wso2.carbon.identity.action.execution.api.model.Failure;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutorService;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.util.ClaimConstants;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.scim2.common.internal.component.SCIMCommonComponentHolder;
import org.wso2.carbon.identity.user.action.api.constant.UserActionError;
import org.wso2.carbon.identity.user.action.api.exception.UserActionExecutionClientException;
import org.wso2.carbon.identity.user.action.api.exception.UserActionExecutionServerException;
import org.wso2.carbon.identity.user.action.api.model.UserActionContext;
import org.wso2.carbon.identity.user.action.api.model.UserActionRequestDTO;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.charon3.core.objects.User;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * This class triggers the execution of the pre update profile extension.
 * This executor should be invoked as user profile updates happen.
 */
public class PreUpdateProfileActionExecutor {

    private static final Log LOG = LogFactory.getLog(PreUpdateProfileActionExecutor.class);
    private static final List<String> NOT_ALLOWED_IDENTITY_CLAIMS = Arrays.asList(
            "http://wso2.org/claims/identity/adminForcedPasswordReset",
            "http://wso2.org/claims/identity/askPassword",
            "http://wso2.org/claims/identity/verifyEmail",
            "http://wso2.org/claims/identity/verifyMobile"
    );

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

        if (!actionExecutorService.isExecutionEnabled(ActionType.PRE_UPDATE_PROFILE) || !isExecutable(
                userClaimsToBeModified, userClaimsToBeDeleted)) {
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

    /**
     * Triggers the execution of pre update profile extension at profile update with PATCH
     *
     * @param user                                             SCIMUserObject reference that updates
     * @param userClaimsExcludingMultiValuedClaimsToBeModified Collection of new claims and existing claims that
     *                                                         updates in the profile, excluding multi-valued claims
     *                                                         with list of values separated with
     *                                                         multi attribute separator
     * @param userClaimsExcludingMultiValuedClaimsToBeDeleted  Collection of existing claims that deletes from the
     *                                                         profile, excluding multi-valued claims with list of
     *                                                         values separated with multi attribute separator
     * @param simpleMultiValuedClaimsToBeAdded                 Collection of claims that updates with a list of values
     *                                                         that are added or updated in existing value set
     * @param simpleMultiValuedClaimsToBeRemoved               Collection of claims that includes a list of values
     *                                                         that are removed from existing value set
     * @param existingClaimsOfUser                             The existing claims of the user
     * @throws UserStoreException If an error occurs while executing the action
     */
    public void execute(User user, Map<String, String> userClaimsExcludingMultiValuedClaimsToBeModified,
                        Map<String, String> userClaimsExcludingMultiValuedClaimsToBeDeleted,
                        Map<String, List<String>> simpleMultiValuedClaimsToBeAdded,
                        Map<String, List<String>> simpleMultiValuedClaimsToBeRemoved,
                        Map<String, String> existingClaimsOfUser)
            throws UserStoreException {

        ActionExecutorService actionExecutorService = SCIMCommonComponentHolder.getActionExecutorService();

        if (!actionExecutorService.isExecutionEnabled(ActionType.PRE_UPDATE_PROFILE) || !isExecutable(
                userClaimsExcludingMultiValuedClaimsToBeModified, userClaimsExcludingMultiValuedClaimsToBeDeleted,
                simpleMultiValuedClaimsToBeAdded, simpleMultiValuedClaimsToBeRemoved)) {
            return;
        }

        LOG.debug("Executing pre update profile action for user: " + user.getId());

        try {
            Map<String, String> multiValuedClaimsToModify = getSimpleMultiValuedClaimsToModify(existingClaimsOfUser,
                    simpleMultiValuedClaimsToBeAdded, simpleMultiValuedClaimsToBeRemoved);

            Map<String, String> userClaimsToBeModified =
                    new HashMap<>(userClaimsExcludingMultiValuedClaimsToBeModified);
            userClaimsToBeModified.putAll(multiValuedClaimsToModify);

            UserActionRequestDTO userActionRequestDTO =
                    buildUserActionRequestDTO(user, userClaimsToBeModified,
                            userClaimsExcludingMultiValuedClaimsToBeDeleted);
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

        UserActionRequestDTO.Builder userActionRequestDTOBuilder = new UserActionRequestDTO.Builder()
                .userId(user.getId());

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

    /**
     * Populate the multi-valued claims to be modified by adding the values to be added and
     * removing the values to be removed from the existing claim values of a particular multi-valued claim of a user.
     *
     * @param existingClaimsOfUser      Existing claims of the user.
     * @param multiValuedClaimsToAdd    Multi-valued claims to be added.
     * @param multiValuedClaimsToDelete Multi-valued claims to be deleted.
     * @return Multi-valued claims to be modified.
     */
    private Map<String, String> getSimpleMultiValuedClaimsToModify(
            Map<String, String> existingClaimsOfUser,
            Map<String, List<String>> multiValuedClaimsToAdd,
            Map<String, List<String>> multiValuedClaimsToDelete) {

        String multiAttributeSeparator = FrameworkUtils.getMultiAttributeSeparator();
        Map<String, String> multiValuedClaimsToModify = new HashMap<>();

        Map<String, List<String>> existingClaimsAsList = existingClaimsOfUser.entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> new ArrayList<>(
                                Arrays.asList(entry.getValue().split(Pattern.quote(multiAttributeSeparator))))));

        Function<String, List<String>> getMutableClaimList = claimURI -> {
            if (multiValuedClaimsToModify.containsKey(claimURI)) {
                return new ArrayList<>(Arrays.asList(
                        multiValuedClaimsToModify.get(claimURI).split(Pattern.quote(multiAttributeSeparator))));
            }
            return new ArrayList<>(existingClaimsAsList.getOrDefault(claimURI, new ArrayList<>()));
        };

        // Add the values to be added to the existing values of each multi-valued claim and
        // construct the new claim value joining the values
        if (multiValuedClaimsToAdd != null) {
            multiValuedClaimsToAdd.forEach((claimURI, valuesToAdd) -> {
                List<String> currentValues = getMutableClaimList.apply(claimURI);
                currentValues.addAll(valuesToAdd);
                multiValuedClaimsToModify.put(claimURI, String.join(multiAttributeSeparator, currentValues));
            });
        }

        // Remove the values to be removed from the existing values of each multi-valued claims
        // and construct the new claim value joining the values
        if (multiValuedClaimsToDelete != null) {
            multiValuedClaimsToDelete.forEach((claimURI, valuesToDelete) -> {
                List<String> currentValues = getMutableClaimList.apply(claimURI);
                if (!currentValues.isEmpty()) {
                    currentValues.removeAll(valuesToDelete);
                    multiValuedClaimsToModify.put(claimURI, String.join(multiAttributeSeparator, currentValues));
                }
            });
        }

        return multiValuedClaimsToModify;
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

    private boolean isExecutable(Map<String, String> userClaimsExcludingMultiValuedClaimsToBeModified,
                                 Map<String, String> userClaimsExcludingMultiValuedClaimsToBeDeleted,
                                 Map<String, List<String>> simpleMultiValuedClaimsToBeAdded,
                                 Map<String, List<String>> simpleMultiValuedClaimsToBeRemoved) {

        if (!MapUtils.isEmpty(userClaimsExcludingMultiValuedClaimsToBeModified) ||
                !MapUtils.isEmpty(userClaimsExcludingMultiValuedClaimsToBeDeleted) ||
                !MapUtils.isEmpty(simpleMultiValuedClaimsToBeAdded) ||
                !MapUtils.isEmpty(simpleMultiValuedClaimsToBeRemoved)) {

            return !onlyContainsNotAllowedIdentityClaims(userClaimsExcludingMultiValuedClaimsToBeModified) ||
                    !onlyContainsNotAllowedIdentityClaims(userClaimsExcludingMultiValuedClaimsToBeDeleted) ||
                    !onlyContainsNotAllowedIdentityClaimsInMultiValuedClaims(simpleMultiValuedClaimsToBeAdded) ||
                    !onlyContainsNotAllowedIdentityClaimsInMultiValuedClaims(simpleMultiValuedClaimsToBeRemoved);
        } else {
            return false;
        }
    }

    private boolean isExecutable(Map<String, String> userClaimsToBeModified,
                                 Map<String, String> userClaimsToBeDeleted) {

        if (!MapUtils.isEmpty(userClaimsToBeModified) || !MapUtils.isEmpty(userClaimsToBeDeleted)) {

            return !onlyContainsNotAllowedIdentityClaims(userClaimsToBeDeleted) ||
                    !onlyContainsNotAllowedIdentityClaims(userClaimsToBeModified);
        } else {
            return false;
        }
    }

    private boolean onlyContainsNotAllowedIdentityClaims(Map<String, String> map) {

        return map.keySet().stream().allMatch(NOT_ALLOWED_IDENTITY_CLAIMS::contains);
    }

    private boolean onlyContainsNotAllowedIdentityClaimsInMultiValuedClaims(Map<String, List<String>> map) {

        return map.keySet().stream().allMatch(NOT_ALLOWED_IDENTITY_CLAIMS::contains) ||
                map.values().stream()
                    .flatMap(List::stream)
                    .allMatch(NOT_ALLOWED_IDENTITY_CLAIMS::contains);
    }
}
