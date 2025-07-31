package org.wso2.carbon.identity.scim2.common.utils;

import org.apache.commons.collections.MapUtils;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.scim2.common.internal.component.SCIMCommonComponentHolder;
import org.wso2.carbon.user.core.UserStoreException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class ExtensionCommonUtils {

    public static boolean isExecutableUserProfileUpdate(Map<String, String> userClaimsToBeModified,
                                                        Map<String, String> userClaimsToBeDeleted) throws
            UserStoreException {

        if (!MapUtils.isEmpty(userClaimsToBeModified) || !MapUtils.isEmpty(userClaimsToBeDeleted)) {

            return hasAnyNonFlowInitiatorClaims(userClaimsToBeDeleted.keySet()) ||
                    hasAnyNonFlowInitiatorClaims(userClaimsToBeModified.keySet());
        }

        return false;
    }

    static boolean hasAnyNonFlowInitiatorClaims(Set<String> claimUriList) throws UserStoreException {

        for (String claimUri : claimUriList) {

            if (!isFlowInitiatorClaim(claimUri)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isFlowInitiatorClaim(String claimUri) throws UserStoreException {

        ClaimMetadataManagementService claimMetadataManagementService = SCIMCommonComponentHolder
                .getClaimManagementService();
        String tenantDomain = IdentityContext.getThreadLocalIdentityContext().getTenantDomain();

        try {
            Optional<LocalClaim> localClaim = claimMetadataManagementService.getLocalClaim(claimUri, tenantDomain);
            return localClaim.isPresent() && localClaim.get().getFlowInitiator();
        } catch (ClaimMetadataException e) {
            throw new UserStoreException(String.format("Error while reading claim meta data of %s", claimUri), e);
        }
    }

    public static boolean isExecutableUserProfileUpdate(
            Map<String, String> userClaimsExcludingMultiValuedClaimsToBeModified,
            Map<String, String> userClaimsExcludingMultiValuedClaimsToBeDeleted,
            Map<String, List<String>> simpleMultiValuedClaimsToBeAdded,
            Map<String, List<String>> simpleMultiValuedClaimsToBeRemoved)
            throws UserStoreException {

        if (!MapUtils.isEmpty(userClaimsExcludingMultiValuedClaimsToBeModified) ||
                !MapUtils.isEmpty(userClaimsExcludingMultiValuedClaimsToBeDeleted) ||
                !MapUtils.isEmpty(simpleMultiValuedClaimsToBeAdded) ||
                !MapUtils.isEmpty(simpleMultiValuedClaimsToBeRemoved)) {

            return hasAnyNonFlowInitiatorClaims(userClaimsExcludingMultiValuedClaimsToBeModified.keySet()) ||
                    hasAnyNonFlowInitiatorClaims(userClaimsExcludingMultiValuedClaimsToBeDeleted.keySet()) ||
                    hasAnyNonFlowInitiatorClaims(simpleMultiValuedClaimsToBeAdded.keySet()) ||
                    hasAnyNonFlowInitiatorClaims(simpleMultiValuedClaimsToBeRemoved.keySet());
        }

        return false;
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
    public static Map<String, String> getSimpleMultiValuedClaimsToModify(
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

    public static void enterFlow(Flow.Name flowName, Flow.InitiatingPersona persona) {

        Flow.InitiatingPersona initiatingPersona = null;
        if (persona != null) {
            initiatingPersona = persona;
        } else if (IdentityContext.getThreadLocalIdentityContext().isApplicationActor()) {
            initiatingPersona = Flow.InitiatingPersona.APPLICATION;
        } else if (IdentityContext.getThreadLocalIdentityContext().isUserActor()) {
            initiatingPersona = Flow.InitiatingPersona.ADMIN;
        }

        Flow flow;
        if (Flow.isCredentialFlow(flowName)) {
            flow = new Flow.CredentialFlowBuilder()
                    .name(flowName)
                    .initiatingPersona(initiatingPersona)
                    .credentialType(Flow.CredentialType.PASSWORD)
                    .build();
        } else {
            flow = new Flow.Builder()
                    .name(flowName)
                    .initiatingPersona(initiatingPersona)
                    .build();
        }
        IdentityContext.getThreadLocalIdentityContext().enterFlow(flow);
    }

    public static void exitFlow() {

        IdentityContext.getThreadLocalIdentityContext().exitFlow();
    }
}
