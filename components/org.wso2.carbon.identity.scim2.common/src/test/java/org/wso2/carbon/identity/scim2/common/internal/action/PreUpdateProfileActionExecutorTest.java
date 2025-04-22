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

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.Error;
import org.wso2.carbon.identity.action.execution.api.model.Failure;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutorService;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.util.ClaimConstants;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.scim2.common.internal.component.SCIMCommonComponentHolder;
import org.wso2.carbon.identity.scim2.common.test.constants.TestConstants;
import org.wso2.carbon.identity.scim2.common.test.utils.CommonTestUtils;
import org.wso2.carbon.identity.user.action.api.constant.UserActionError;
import org.wso2.carbon.identity.user.action.api.exception.UserActionExecutionClientException;
import org.wso2.carbon.identity.user.action.api.exception.UserActionExecutionServerException;
import org.wso2.carbon.identity.user.action.api.model.UserActionContext;
import org.wso2.carbon.identity.user.action.api.model.UserActionRequestDTO;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.objects.User;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertTrue;
import static org.testng.internal.junit.ArrayAsserts.assertArrayEquals;
import static org.wso2.carbon.identity.scim2.common.test.constants.TestConstants.Claims.DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM8;
import static org.wso2.carbon.identity.scim2.common.test.constants.TestConstants.Claims.DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM8;
import static org.wso2.carbon.identity.scim2.common.test.constants.TestConstants.Claims.DELETING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM5;
import static org.wso2.carbon.identity.scim2.common.test.constants.TestConstants.Claims.DELETING_SINGLEVALUE_CLAIM4;
import static org.wso2.carbon.identity.scim2.common.test.constants.TestConstants.Claims.FLOW_INITIATOR_SINGLEVALUE_IDENTITY_CLAIM1;
import static org.wso2.carbon.identity.scim2.common.test.constants.TestConstants.Claims.NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM6;
import static org.wso2.carbon.identity.scim2.common.test.constants.TestConstants.Claims.NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM6;
import static org.wso2.carbon.identity.scim2.common.test.constants.TestConstants.Claims.NEW_SINGLEVALUE_CLAIM1;
import static org.wso2.carbon.identity.scim2.common.test.constants.TestConstants.Claims.UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM7;
import static org.wso2.carbon.identity.scim2.common.test.constants.TestConstants.Claims.UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7;
import static org.wso2.carbon.identity.scim2.common.test.constants.TestConstants.Claims.UPDATING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM3;
import static org.wso2.carbon.identity.scim2.common.test.constants.TestConstants.Claims.UPDATING_SINGLEVALUE_CLAIM2;

/**
 * Test class for PreUpdateProfileActionExecutor.
 */
public class PreUpdateProfileActionExecutorTest {

    @Mock
    private ActionExecutorService actionExecutorService;

    @Mock
    private ClaimMetadataManagementService claimMetadataManagementService;

    private PreUpdateProfileActionExecutor preUpdateProfileActionExecutor;

    private MockedStatic<FrameworkUtils> frameworkUtils;

    @BeforeMethod
    public void setUp() throws Exception {

        MockitoAnnotations.openMocks(this);
        SCIMCommonComponentHolder.setActionExecutorService(actionExecutorService);
        SCIMCommonComponentHolder.setClaimManagementService(claimMetadataManagementService);

        frameworkUtils = mockStatic(FrameworkUtils.class);
        frameworkUtils.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(",");

        preUpdateProfileActionExecutor = new PreUpdateProfileActionExecutor();

        CommonTestUtils.initPrivilegedCarbonContext();
    }

    @AfterMethod
    public void tearDown() {

        IdentityContext.destroyCurrentContext();
        PrivilegedCarbonContext.endTenantFlow();

        frameworkUtils.close();
        Mockito.reset(actionExecutorService, claimMetadataManagementService);
    }

    @Test
    public void testExecutionWhenActionExecutionIsDisabled() throws Exception {

        when(actionExecutorService.isExecutionEnabled(ActionType.PRE_UPDATE_PROFILE)).thenReturn(false);

        User user = getSCIMUser();

        preUpdateProfileActionExecutor.execute(user, Collections.emptyMap(), Collections.emptyMap());
        verify(actionExecutorService, Mockito.never()).execute(any(), any(), any());

        preUpdateProfileActionExecutor.execute(user, Collections.emptyMap(), Collections.emptyMap(),
                Collections.emptyMap(), Collections.emptyMap(), Collections.emptyMap());
        verify(actionExecutorService, Mockito.never()).execute(any(), any(), any());
    }

    @Test
    public void testSuccessExecutionForClaimUpdateExecutionAtPutOperation() throws Exception {

        when(actionExecutorService.isExecutionEnabled(ActionType.PRE_UPDATE_PROFILE)).thenReturn(true);

        ActionExecutionStatus status = mock(ActionExecutionStatus.class);
        when(status.getStatus()).thenReturn(ActionExecutionStatus.Status.SUCCESS);
        when(actionExecutorService.execute(eq(ActionType.PRE_UPDATE_PROFILE), any(), any())).thenReturn(status);

        LocalClaim newClaim = getMockedLocalClaim(NEW_SINGLEVALUE_CLAIM1);
        LocalClaim deletingClaim = getMockedLocalClaim(DELETING_SINGLEVALUE_CLAIM4);
        when(claimMetadataManagementService.getLocalClaim(eq(NEW_SINGLEVALUE_CLAIM1.getClaimURI()), any(String.class)))
                .thenReturn(Optional.of(newClaim));
        when(claimMetadataManagementService.getLocalClaim(eq(DELETING_SINGLEVALUE_CLAIM4.getClaimURI()),
                any(String.class))).thenReturn(Optional.of(deletingClaim));

        User user = getSCIMUser();

        Map<String, String> claimsToModify = new HashMap<>();
        claimsToModify.put(NEW_SINGLEVALUE_CLAIM1.getClaimURI(), NEW_SINGLEVALUE_CLAIM1.getInputValueAsString());

        Map<String, String> claimsToDelete = new HashMap<>();
        claimsToDelete.put(DELETING_SINGLEVALUE_CLAIM4.getClaimURI(),
                DELETING_SINGLEVALUE_CLAIM4.getInputValueAsString());

        preUpdateProfileActionExecutor.execute(user, claimsToModify, claimsToDelete);
        verify(actionExecutorService).execute(eq(ActionType.PRE_UPDATE_PROFILE), any(), any());
    }

    @Test
    public void testFailureExecutionForClaimUpdateExecutionAtPutOperation() throws Exception {

        when(actionExecutorService.isExecutionEnabled(ActionType.PRE_UPDATE_PROFILE)).thenReturn(true);

        ActionExecutionStatus status = mock(ActionExecutionStatus.class);
        when(status.getStatus()).thenReturn(ActionExecutionStatus.Status.FAILED);
        Failure failure = new Failure("failureReason", "failureDescription");
        when(status.getResponse()).thenReturn(failure);
        when(actionExecutorService.execute(eq(ActionType.PRE_UPDATE_PROFILE), any(), any())).thenReturn(status);

        LocalClaim newClaim = getMockedLocalClaim(NEW_SINGLEVALUE_CLAIM1);
        LocalClaim deletingClaim = getMockedLocalClaim(DELETING_SINGLEVALUE_CLAIM4);
        when(claimMetadataManagementService.getLocalClaim(eq(NEW_SINGLEVALUE_CLAIM1.getClaimURI()), any(String.class)))
                .thenReturn(Optional.of(newClaim));
        when(claimMetadataManagementService.getLocalClaim(eq(DELETING_SINGLEVALUE_CLAIM4.getClaimURI()),
                any(String.class))).thenReturn(Optional.of(deletingClaim));

        User user = getSCIMUser();

        Map<String, String> claimsToModify = new HashMap<>();
        claimsToModify.put(NEW_SINGLEVALUE_CLAIM1.getClaimURI(), NEW_SINGLEVALUE_CLAIM1.getInputValueAsString());

        Map<String, String> claimsToDelete = new HashMap<>();
        claimsToDelete.put(DELETING_SINGLEVALUE_CLAIM4.getClaimURI(),
                DELETING_SINGLEVALUE_CLAIM4.getInputValueAsString());

        try {
            preUpdateProfileActionExecutor.execute(user, claimsToModify, claimsToDelete);
            fail("Expected UserActionExecutionClientException to be thrown");
        } catch (UserActionExecutionClientException e) {
            assertEquals(e.getErrorCode(), UserActionError.PRE_UPDATE_PROFILE_ACTION_EXECUTION_FAILED);
            assertEquals(e.getError(), "failureReason");
            assertEquals(e.getDescription(), "failureDescription");
            assertEquals(e.getMessage(), "failureReason. failureDescription");
        }
    }

    @Test
    public void testErrorExecutionForClaimUpdateExecutionAtPutOperation() throws Exception {

        when(actionExecutorService.isExecutionEnabled(ActionType.PRE_UPDATE_PROFILE)).thenReturn(true);

        ActionExecutionStatus status = mock(ActionExecutionStatus.class);
        when(status.getStatus()).thenReturn(ActionExecutionStatus.Status.ERROR);
        Error error = new Error("errorMessage", "errorDescription");
        when(status.getResponse()).thenReturn(error);
        when(actionExecutorService.execute(eq(ActionType.PRE_UPDATE_PROFILE), any(), any())).thenReturn(status);

        LocalClaim newClaim = getMockedLocalClaim(NEW_SINGLEVALUE_CLAIM1);
        LocalClaim deletingClaim = getMockedLocalClaim(DELETING_SINGLEVALUE_CLAIM4);
        when(claimMetadataManagementService.getLocalClaim(eq(NEW_SINGLEVALUE_CLAIM1.getClaimURI()), any(String.class)))
                .thenReturn(Optional.of(newClaim));
        when(claimMetadataManagementService.getLocalClaim(eq(DELETING_SINGLEVALUE_CLAIM4.getClaimURI()),
                any(String.class))).thenReturn(Optional.of(deletingClaim));

        User user = getSCIMUser();

        Map<String, String> claimsToModify = new HashMap<>();
        claimsToModify.put(NEW_SINGLEVALUE_CLAIM1.getClaimURI(), NEW_SINGLEVALUE_CLAIM1.getInputValueAsString());

        Map<String, String> claimsToDelete = new HashMap<>();
        claimsToDelete.put(DELETING_SINGLEVALUE_CLAIM4.getClaimURI(),
                DELETING_SINGLEVALUE_CLAIM4.getInputValueAsString());

        try {
            preUpdateProfileActionExecutor.execute(user, claimsToModify, claimsToDelete);
            fail("Expected UserActionExecutionClientException to be thrown");
        } catch (UserActionExecutionServerException e) {
            assertEquals(e.getErrorCode(), UserActionError.PRE_UPDATE_PROFILE_ACTION_EXECUTION_ERROR);
            assertEquals(e.getError(), "errorMessage");
            assertEquals(e.getDescription(), "errorDescription");
            assertEquals(e.getMessage(), "errorMessage. errorDescription");
        }
    }

    @Test
    public void testExecutionSkippedForFlowInitiatorClaimUpdateExecutionAtPutOperation() throws Exception {

        when(actionExecutorService.isExecutionEnabled(ActionType.PRE_UPDATE_PROFILE)).thenReturn(true);

        ActionExecutionStatus status = mock(ActionExecutionStatus.class);
        when(status.getStatus()).thenReturn(ActionExecutionStatus.Status.SUCCESS);
        when(actionExecutorService.execute(eq(ActionType.PRE_UPDATE_PROFILE), any(), any())).thenReturn(status);

        LocalClaim newClaim = getMockedLocalClaim(FLOW_INITIATOR_SINGLEVALUE_IDENTITY_CLAIM1);
        when(claimMetadataManagementService.getLocalClaim(eq(FLOW_INITIATOR_SINGLEVALUE_IDENTITY_CLAIM1.getClaimURI()),
                anyString())).thenReturn(Optional.of(newClaim));
        when(newClaim.getFlowInitiator()).thenReturn(true);

        User user = getSCIMUser();

        Map<String, String> claimsToModify = new HashMap<>();
        claimsToModify.put(FLOW_INITIATOR_SINGLEVALUE_IDENTITY_CLAIM1.getClaimURI(),
                FLOW_INITIATOR_SINGLEVALUE_IDENTITY_CLAIM1.getInputValueAsString());

        Map<String, String> claimsToDelete = new HashMap<>();

        preUpdateProfileActionExecutor.execute(user, claimsToModify, claimsToDelete);
        verify(actionExecutorService, never()).execute(eq(ActionType.PRE_UPDATE_PROFILE), any(), any());
    }

    @Test
    public void testSuccessExecutionForNoClaimUpdateExecutionAtPutOperation() throws Exception {

        when(actionExecutorService.isExecutionEnabled(ActionType.PRE_UPDATE_PROFILE)).thenReturn(true);

        ActionExecutionStatus status = mock(ActionExecutionStatus.class);
        when(status.getStatus()).thenReturn(ActionExecutionStatus.Status.SUCCESS);
        when(actionExecutorService.execute(eq(ActionType.PRE_UPDATE_PROFILE), any(), any())).thenReturn(status);

        User user = getSCIMUser();

        Map<String, String> claimsToModify = new HashMap<>();

        Map<String, String> claimsToDelete = new HashMap<>();

        preUpdateProfileActionExecutor.execute(user, claimsToModify, claimsToDelete);
        verify(actionExecutorService, never()).execute(eq(ActionType.PRE_UPDATE_PROFILE), any(), any());
    }

    @Test
    public void testSuccessExecutionForClaimUpdateExecutionAtPatchOperation() throws Exception {

        when(actionExecutorService.isExecutionEnabled(ActionType.PRE_UPDATE_PROFILE)).thenReturn(true);

        ActionExecutionStatus status = mock(ActionExecutionStatus.class);
        when(status.getStatus()).thenReturn(ActionExecutionStatus.Status.SUCCESS);
        when(actionExecutorService.execute(eq(ActionType.PRE_UPDATE_PROFILE), any(), any())).thenReturn(status);

        // Mock claim metadata for multi valued claims
        LocalClaim newMultiValuedClaim = getMockedLocalClaim(NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM6);
        LocalClaim modifiedMultiValuedClaim =
                getMockedLocalClaim(UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7);
        LocalClaim deletingMultiValuedClaim = getMockedLocalClaim(DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM8);

        when(claimMetadataManagementService.getLocalClaim(eq(
                NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM6.getClaimURI()), any(String.class)))
                .thenReturn(Optional.of(newMultiValuedClaim));
        when(claimMetadataManagementService.getLocalClaim(eq(
                        UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7.getClaimURI()),
                any(String.class))).thenReturn(Optional.of(modifiedMultiValuedClaim));
        when(claimMetadataManagementService.getLocalClaim(eq(
                        DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM8.getClaimURI()),
                any(String.class))).thenReturn(Optional.of(deletingMultiValuedClaim));

        // Mock claim metadata for single valued claims
        LocalClaim newSingleValuedClaim = getMockedLocalClaim(NEW_SINGLEVALUE_CLAIM1);
        LocalClaim deletingSingleValuedClaim = getMockedLocalClaim(DELETING_SINGLEVALUE_CLAIM4);

        when(claimMetadataManagementService.getLocalClaim(eq(NEW_SINGLEVALUE_CLAIM1.getClaimURI()), any(String.class)))
                .thenReturn(Optional.of(newSingleValuedClaim));
        when(claimMetadataManagementService.getLocalClaim(eq(DELETING_SINGLEVALUE_CLAIM4.getClaimURI()),
                any(String.class))).thenReturn(Optional.of(deletingSingleValuedClaim));

        User user = getSCIMUser();

        // Setup updating and deleting claims maps to invoke the action execution method
        Map<String, String> userClaimsExcludingMultiValuedClaimsToBeModified = new HashMap<>();
        userClaimsExcludingMultiValuedClaimsToBeModified.put(NEW_SINGLEVALUE_CLAIM1.getClaimURI(),
                NEW_SINGLEVALUE_CLAIM1.getInputValueAsString());

        Map<String, String> userClaimsExcludingMultiValuedClaimsToBeDeleted = new HashMap<>();
        userClaimsExcludingMultiValuedClaimsToBeDeleted.put(DELETING_SINGLEVALUE_CLAIM4.getClaimURI(),
                DELETING_SINGLEVALUE_CLAIM4.getInputValueAsString());

        Map<String, List<String>> simpleMultiValuedClaimsToBeAdded = new HashMap<>();
        simpleMultiValuedClaimsToBeAdded.put(NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM6.getClaimURI(),
                NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM6.getInputValueAsStringList());
        simpleMultiValuedClaimsToBeAdded.put(UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7.getClaimURI(),
                UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7.getInputValueAsStringList());
        Map<String, List<String>> simpleMultiValuedClaimsToBeRemoved = new HashMap<>();
        simpleMultiValuedClaimsToBeRemoved.put(DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM8.getClaimURI(),
                DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM8.getInputValueAsStringList());

        Map<String, String> existingClaimsOfUser = new HashMap<>();
        existingClaimsOfUser.put(UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7.getClaimURI(),
                UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7.getExistingValueInUser());
        existingClaimsOfUser.put(DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM8.getClaimURI(),
                DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM8.getExistingValueInUser());
        existingClaimsOfUser.put(UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7.getClaimURI(),
                UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7.getExistingValueInUser());
        existingClaimsOfUser.put(DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM8.getClaimURI(),
                DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM8.getExistingValueInUser());

        preUpdateProfileActionExecutor.execute(user,
                userClaimsExcludingMultiValuedClaimsToBeModified,
                userClaimsExcludingMultiValuedClaimsToBeDeleted,
                simpleMultiValuedClaimsToBeAdded,
                simpleMultiValuedClaimsToBeRemoved,
                existingClaimsOfUser);

        verify(actionExecutorService).execute(eq(ActionType.PRE_UPDATE_PROFILE), any(), any());
    }

    @Test
    public void testUserActionRequestDTOForClaimUpdateExecutionAtPutOperation() throws Exception {

        when(actionExecutorService.isExecutionEnabled(ActionType.PRE_UPDATE_PROFILE)).thenReturn(true);

        ActionExecutionStatus<?> status = mock(ActionExecutionStatus.class);
        when(status.getStatus()).thenReturn(ActionExecutionStatus.Status.SUCCESS);
        when(actionExecutorService.execute(eq(ActionType.PRE_UPDATE_PROFILE), any(), any())).thenReturn(status);

        // Mock claim metadata for added and modified claims
        LocalClaim newSingleValuedClaim = getMockedLocalClaim(NEW_SINGLEVALUE_CLAIM1);
        LocalClaim modifiedSingleValuedClaim = getMockedLocalClaim(UPDATING_SINGLEVALUE_CLAIM2);
        LocalClaim modifiedMultiAttributeSeparatorIncludedSingleValuedClaim =
                getMockedLocalClaim(UPDATING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM3);
        LocalClaim newMultiValueClaim = getMockedLocalClaim(NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM6);
        LocalClaim modifiedMultiValueClaim = getMockedLocalClaim(UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM7);

        when(claimMetadataManagementService.getLocalClaim(eq(NEW_SINGLEVALUE_CLAIM1.getClaimURI()), any(String.class)))
                .thenReturn(Optional.of(newSingleValuedClaim));
        when(claimMetadataManagementService.getLocalClaim(eq(UPDATING_SINGLEVALUE_CLAIM2.getClaimURI()),
                any(String.class)))
                .thenReturn(Optional.of(modifiedSingleValuedClaim));
        when(claimMetadataManagementService.getLocalClaim(
                eq(UPDATING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM3.getClaimURI()),
                any(String.class))).thenReturn(Optional.of(modifiedMultiAttributeSeparatorIncludedSingleValuedClaim));
        when(claimMetadataManagementService.getLocalClaim(eq(NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM6.getClaimURI()),
                any(String.class))).thenReturn(Optional.of(newMultiValueClaim));
        when(claimMetadataManagementService.getLocalClaim(
                eq(UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM7.getClaimURI()),
                any(String.class))).thenReturn(Optional.of(modifiedMultiValueClaim));

        // Mock claim metadata for deleted claims
        LocalClaim deletingSingleValuedClaim = getMockedLocalClaim(DELETING_SINGLEVALUE_CLAIM4);
        LocalClaim deletingMultiAttributeSeparatorIncludedSingleValuedClaim =
                getMockedLocalClaim(DELETING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM5);
        LocalClaim deletingMultiValuedClaim =
                getMockedLocalClaim(DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM8);
        when(claimMetadataManagementService.getLocalClaim(eq(DELETING_SINGLEVALUE_CLAIM4.getClaimURI()),
                any(String.class))).thenReturn(Optional.of(deletingSingleValuedClaim));
        when(claimMetadataManagementService.getLocalClaim(
                eq(DELETING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM5.getClaimURI()),
                any(String.class))).thenReturn(Optional.of(deletingMultiAttributeSeparatorIncludedSingleValuedClaim));
        when(claimMetadataManagementService.getLocalClaim(
                eq(DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM8.getClaimURI()),
                any(String.class))).thenReturn(Optional.of(deletingMultiValuedClaim));

        User user = getSCIMUser();

        // Setup updating claim map to invoke the action execution method
        Map<String, String> claimsToModify = new HashMap<>();
        claimsToModify.put(NEW_SINGLEVALUE_CLAIM1.getClaimURI(), NEW_SINGLEVALUE_CLAIM1.getInputValueAsString());
        claimsToModify.put(UPDATING_SINGLEVALUE_CLAIM2.getClaimURI(),
                UPDATING_SINGLEVALUE_CLAIM2.getInputValueAsString());
        claimsToModify.put(UPDATING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM3.getClaimURI(),
                UPDATING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM3.getInputValueAsString());
        claimsToModify.put(NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM6.getClaimURI(),
                NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM6.getInputValueAsString());
        claimsToModify.put(UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM7.getClaimURI(),
                UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM7.getInputValueAsString());

        // Setup deleting claim map to invoke the action execution method
        Map<String, String> claimsToDelete = new HashMap<>();
        claimsToDelete.put(DELETING_SINGLEVALUE_CLAIM4.getClaimURI(),
                DELETING_SINGLEVALUE_CLAIM4.getInputValueAsString());
        claimsToDelete.put(DELETING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM5.getClaimURI(),
                DELETING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM5.getInputValueAsString());
        claimsToDelete.put(DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM8.getClaimURI(),
                DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM8.getInputValueAsString());

        // Invoke the execute method.
        preUpdateProfileActionExecutor.execute(user, claimsToModify, claimsToDelete);

        // Retrieve the UserActionRequestDTO.
        ArgumentCaptor<FlowContext> flowContextCaptor = ArgumentCaptor.forClass(FlowContext.class);
        verify(actionExecutorService).execute(eq(ActionType.PRE_UPDATE_PROFILE), flowContextCaptor.capture(), any());
        FlowContext capturedFlowContext = flowContextCaptor.getValue();

        Object userActionContextObj =
                capturedFlowContext.getContextData().get(UserActionContext.USER_ACTION_CONTEXT_REFERENCE_KEY);
        assertNotNull(userActionContextObj);
        assertTrue(userActionContextObj instanceof UserActionContext);
        UserActionContext userActionContext = (UserActionContext) userActionContextObj;

        UserActionRequestDTO requestDTO = userActionContext.getUserActionRequestDTO();
        assertNotNull(requestDTO);

        Map<String, Object> claims = requestDTO.getClaims();
        assertEquals(claims.size(), 8);
        // Verify that the modified claim exists.
        // Single valued claims should return a String whereas multi valued claims should return a String[]
        assertTrue(claims.containsKey(NEW_SINGLEVALUE_CLAIM1.getClaimURI()));
        assertEquals(claims.get(NEW_SINGLEVALUE_CLAIM1.getClaimURI()),
                NEW_SINGLEVALUE_CLAIM1.getExpectedValueInDTOAsString());
        assertTrue(claims.containsKey(UPDATING_SINGLEVALUE_CLAIM2.getClaimURI()));
        assertEquals(claims.get(UPDATING_SINGLEVALUE_CLAIM2.getClaimURI()),
                UPDATING_SINGLEVALUE_CLAIM2.getExpectedValueInDTOAsString());
        assertTrue(claims.containsKey(UPDATING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM3.getClaimURI()));
        assertEquals(claims.get(UPDATING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM3.getClaimURI()),
                UPDATING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM3.getExpectedValueInDTOAsString());
        assertTrue(claims.containsKey(NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM6.getClaimURI()));
        assertArrayEquals((String[]) claims.get(NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM6.getClaimURI()),
                NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM6.getExpectedValueInDTOAsStringArray());
        assertTrue(claims.containsKey(UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7.getClaimURI()));
        assertArrayEquals((String[]) claims.get(UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM7.getClaimURI()),
                UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM7.getExpectedValueInDTOAsStringArray());

        // Verify deleted claims.
        // Single valued claims should return an empty String,
        // whereas multi valued claims should return an empty String[]
        assertTrue(claims.containsKey(DELETING_SINGLEVALUE_CLAIM4.getClaimURI()));
        assertEquals(claims.get(DELETING_SINGLEVALUE_CLAIM4.getClaimURI()),
                DELETING_SINGLEVALUE_CLAIM4.getExpectedValueInDTOAsString());
        assertTrue(claims.containsKey(DELETING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM5.getClaimURI()));
        assertEquals(claims.get(DELETING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM5.getClaimURI()),
                DELETING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM5.getExpectedValueInDTOAsString());
        assertTrue(claims.containsKey(DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM8.getClaimURI()));
        assertArrayEquals((String[]) claims.get(DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM8.getClaimURI()),
                DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM8.getExpectedValueInDTOAsStringArray());
    }

    @Test
    public void testUserActionRequestDTOForClaimUpdateExecutionInPatchOperation() throws Exception {

        when(actionExecutorService.isExecutionEnabled(ActionType.PRE_UPDATE_PROFILE)).thenReturn(true);

        ActionExecutionStatus<?> status = mock(ActionExecutionStatus.class);
        when(status.getStatus()).thenReturn(ActionExecutionStatus.Status.SUCCESS);
        when(actionExecutorService.execute(eq(ActionType.PRE_UPDATE_PROFILE), any(), any())).thenReturn(status);

        // Mock claim metadata for added and modified single valued claims
        LocalClaim newSingleValuedClaim = getMockedLocalClaim(NEW_SINGLEVALUE_CLAIM1);
        LocalClaim modifiedSingleValuedClaim = getMockedLocalClaim(UPDATING_SINGLEVALUE_CLAIM2);
        LocalClaim modifiedMultiAttributeSeparatorIncludedSingleValuedClaim =
                getMockedLocalClaim(UPDATING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM3);

        when(claimMetadataManagementService.getLocalClaim(eq(NEW_SINGLEVALUE_CLAIM1.getClaimURI()), any(String.class)))
                .thenReturn(Optional.of(newSingleValuedClaim));
        when(claimMetadataManagementService.getLocalClaim(eq(UPDATING_SINGLEVALUE_CLAIM2.getClaimURI()),
                any(String.class)))
                .thenReturn(Optional.of(modifiedSingleValuedClaim));
        when(claimMetadataManagementService.getLocalClaim(
                eq(UPDATING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM3.getClaimURI()),
                any(String.class))).thenReturn(Optional.of(modifiedMultiAttributeSeparatorIncludedSingleValuedClaim));

        // Mock claim metadata for deleted single valued claims
        LocalClaim deletingSingleValuedClaim = getMockedLocalClaim(DELETING_SINGLEVALUE_CLAIM4);
        LocalClaim deletingMultiAttributeSeparatorIncludedSingleValuedClaim =
                getMockedLocalClaim(DELETING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM5);
        when(claimMetadataManagementService.getLocalClaim(eq(DELETING_SINGLEVALUE_CLAIM4.getClaimURI()),
                any(String.class))).thenReturn(Optional.of(deletingSingleValuedClaim));
        when(claimMetadataManagementService.getLocalClaim(
                eq(DELETING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM5.getClaimURI()),
                any(String.class))).thenReturn(Optional.of(deletingMultiAttributeSeparatorIncludedSingleValuedClaim));

        // Mock claim metadata for added or modified values of multi valued claims
        LocalClaim newMultiValueClaim = getMockedLocalClaim(NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM6);
        LocalClaim modifiedMultiValueClaim = getMockedLocalClaim(UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7);
        when(claimMetadataManagementService.getLocalClaim(
                eq(NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM6.getClaimURI()),
                any(String.class))).thenReturn(Optional.of(newMultiValueClaim));
        when(claimMetadataManagementService.getLocalClaim(
                eq(UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7.getClaimURI()),
                any(String.class))).thenReturn(Optional.of(modifiedMultiValueClaim));

        // Mock claim metadata for deleted values of multi valued claims
        LocalClaim deletingMultiValuedClaim =
                getMockedLocalClaim(DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM8);
        when(claimMetadataManagementService.getLocalClaim(
                eq(DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM8.getClaimURI()),
                any(String.class))).thenReturn(Optional.of(deletingMultiValuedClaim));

        User user = getSCIMUser();

        // Setup updating and deleting claims maps to invoke the action execution method
        Map<String, String> userClaimsExcludingMultiValuedClaimsToBeModified = new HashMap<>();
        userClaimsExcludingMultiValuedClaimsToBeModified.put(NEW_SINGLEVALUE_CLAIM1.getClaimURI(),
                NEW_SINGLEVALUE_CLAIM1.getInputValueAsString());
        userClaimsExcludingMultiValuedClaimsToBeModified.put(UPDATING_SINGLEVALUE_CLAIM2.getClaimURI(),
                UPDATING_SINGLEVALUE_CLAIM2.getInputValueAsString());
        userClaimsExcludingMultiValuedClaimsToBeModified.put(
                UPDATING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM3.getClaimURI(),
                UPDATING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM3.getInputValueAsString());

        Map<String, String> userClaimsExcludingMultiValuedClaimsToBeDeleted = new HashMap<>();
        userClaimsExcludingMultiValuedClaimsToBeDeleted.put(DELETING_SINGLEVALUE_CLAIM4.getClaimURI(),
                DELETING_SINGLEVALUE_CLAIM4.getInputValueAsString());
        userClaimsExcludingMultiValuedClaimsToBeDeleted.put(
                DELETING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM5.getClaimURI(),
                DELETING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM5.getInputValueAsString());

        Map<String, List<String>> simpleMultiValuedClaimsToBeAdded = new HashMap<>();
        simpleMultiValuedClaimsToBeAdded.put(NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM6.getClaimURI(),
                NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM6.getInputValueAsStringList());
        simpleMultiValuedClaimsToBeAdded.put(UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7.getClaimURI(),
                UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7.getInputValueAsStringList());

        Map<String, List<String>> simpleMultiValuedClaimsToBeRemoved = new HashMap<>();
        simpleMultiValuedClaimsToBeRemoved.put(DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM8.getClaimURI(),
                DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM8.getInputValueAsStringList());

        Map<String, String> existingClaimsOfUser = new HashMap<>();
        existingClaimsOfUser.put(UPDATING_SINGLEVALUE_CLAIM2.getClaimURI(),
                UPDATING_SINGLEVALUE_CLAIM2.getExistingValueInUser());
        existingClaimsOfUser.put(UPDATING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM3.getClaimURI(),
                UPDATING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM3.getExistingValueInUser());
        existingClaimsOfUser.put(DELETING_SINGLEVALUE_CLAIM4.getClaimURI(),
                DELETING_SINGLEVALUE_CLAIM4.getExistingValueInUser());
        existingClaimsOfUser.put(DELETING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM5.getClaimURI(),
                DELETING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM5.getExistingValueInUser());
        existingClaimsOfUser.put(UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7.getClaimURI(),
                UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7.getExistingValueInUser());
        existingClaimsOfUser.put(DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM8.getClaimURI(),
                DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_CLAIM8.getExistingValueInUser());
        existingClaimsOfUser.put(DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM8.getClaimURI(),
                DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM8.getExistingValueInUser());

        preUpdateProfileActionExecutor.execute(user,
                userClaimsExcludingMultiValuedClaimsToBeModified,
                userClaimsExcludingMultiValuedClaimsToBeDeleted,
                simpleMultiValuedClaimsToBeAdded,
                simpleMultiValuedClaimsToBeRemoved,
                existingClaimsOfUser);

        // Retrieve the UserActionRequestDTO.
        ArgumentCaptor<FlowContext> flowContextCaptor = ArgumentCaptor.forClass(FlowContext.class);
        verify(actionExecutorService).execute(eq(ActionType.PRE_UPDATE_PROFILE), flowContextCaptor.capture(), any());
        FlowContext capturedFlowContext = flowContextCaptor.getValue();

        Object userActionContextObj =
                capturedFlowContext.getContextData().get(UserActionContext.USER_ACTION_CONTEXT_REFERENCE_KEY);
        assertNotNull(userActionContextObj);
        assertTrue(userActionContextObj instanceof UserActionContext);
        UserActionContext userActionContext = (UserActionContext) userActionContextObj;

        UserActionRequestDTO requestDTO = userActionContext.getUserActionRequestDTO();
        assertNotNull(requestDTO);

        Map<String, Object> claims = requestDTO.getClaims();
        assertEquals(claims.size(), 8);
        // Verify that the modified claim exists.
        // Single valued claims modified should return a String
        assertTrue(claims.containsKey(NEW_SINGLEVALUE_CLAIM1.getClaimURI()));
        assertEquals(claims.get(NEW_SINGLEVALUE_CLAIM1.getClaimURI()),
                NEW_SINGLEVALUE_CLAIM1.getExpectedValueInDTOAsString());
        assertTrue(claims.containsKey(UPDATING_SINGLEVALUE_CLAIM2.getClaimURI()));
        assertEquals(claims.get(UPDATING_SINGLEVALUE_CLAIM2.getClaimURI()),
                UPDATING_SINGLEVALUE_CLAIM2.getExpectedValueInDTOAsString());
        assertTrue(claims.containsKey(UPDATING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM3.getClaimURI()));
        assertEquals(claims.get(UPDATING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM3.getClaimURI()),
                UPDATING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM3.getExpectedValueInDTOAsString());
        // Multi valued claims modified should return a String[] modifying only values modified
        assertTrue(claims.containsKey(NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM6.getClaimURI()));
        assertArrayEquals((String[]) claims.get(NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM6.getClaimURI()),
                NEW_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM6.getExpectedValueInDTOAsStringArray());
        assertTrue(claims.containsKey(UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7.getClaimURI()));
        assertArrayEquals((String[]) claims.get(UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7.getClaimURI()),
                UPDATING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM7.getExpectedValueInDTOAsStringArray());

        // Verify deleted claims.
        // Single valued claims should return an empty String
        assertTrue(claims.containsKey(DELETING_SINGLEVALUE_CLAIM4.getClaimURI()));
        assertEquals(claims.get(DELETING_SINGLEVALUE_CLAIM4.getClaimURI()),
                DELETING_SINGLEVALUE_CLAIM4.getExpectedValueInDTOAsString());
        assertTrue(claims.containsKey(DELETING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM5.getClaimURI()));
        assertEquals(claims.get(DELETING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM5.getClaimURI()),
                DELETING_MULTI_ATTRIBUTE_SEPARATOR_INCLUDED_SINGLEVALUE_CLAIM5.getExpectedValueInDTOAsString());
        // Multi valued claims should return a String[] removing values to be deleted from value list
        assertTrue(claims.containsKey(DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM8.getClaimURI()));
        assertArrayEquals((String[]) claims.get(DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM8.getClaimURI()),
                DELETING_MULTIVALUE_INPUT_VALUE_AS_STRING_LIST_CLAIM8.getExpectedValueInDTOAsStringArray());
    }

    @Test
    public void testSuccessExecutionForNoClaimUpdateExecutionAtPatchOperation() throws Exception {

        when(actionExecutorService.isExecutionEnabled(ActionType.PRE_UPDATE_PROFILE)).thenReturn(true);

        ActionExecutionStatus status = mock(ActionExecutionStatus.class);
        when(status.getStatus()).thenReturn(ActionExecutionStatus.Status.SUCCESS);
        when(actionExecutorService.execute(eq(ActionType.PRE_UPDATE_PROFILE), any(), any())).thenReturn(status);

        User user = getSCIMUser();

        // Setup updating and deleting claims maps to invoke the action execution method
        Map<String, String> userClaimsExcludingMultiValuedClaimsToBeModified = new HashMap<>();

        Map<String, String> userClaimsExcludingMultiValuedClaimsToBeDeleted = new HashMap<>();

        Map<String, List<String>> simpleMultiValuedClaimsToBeAdded = new HashMap<>();

        Map<String, List<String>> simpleMultiValuedClaimsToBeRemoved = new HashMap<>();

        Map<String, String> existingClaimsOfUser = new HashMap<>();

        preUpdateProfileActionExecutor.execute(user,
                userClaimsExcludingMultiValuedClaimsToBeModified,
                userClaimsExcludingMultiValuedClaimsToBeDeleted,
                simpleMultiValuedClaimsToBeAdded,
                simpleMultiValuedClaimsToBeRemoved,
                existingClaimsOfUser);

        verify(actionExecutorService, never()).execute(eq(ActionType.PRE_UPDATE_PROFILE), any(), any());
    }

    private static User getSCIMUser() throws CharonException, BadRequestException {

        User user = new User();
        user.setId(TestConstants.TEST_USER_ID);
        user.setUserName(TestConstants.TEST_USER_USERNAME);

        return user;
    }

    private static LocalClaim getMockedLocalClaim(TestConstants.Claims claim) {

        return claim.isMultiValued() ? mockLocalMultiValuedClaim(claim.getClaimURI()) :
                mockLocalSingleValuedClaim(claim.getClaimURI());
    }

    private static LocalClaim mockLocalMultiValuedClaim(String claimUri) {

        LocalClaim localClaim = mock(LocalClaim.class);
        when(localClaim.getClaimURI()).thenReturn(claimUri);
        when(localClaim.getClaimProperty(ClaimConstants.MULTI_VALUED_PROPERTY)).thenReturn("true");

        return localClaim;
    }

    private static LocalClaim mockLocalSingleValuedClaim(String claimUri) {

        LocalClaim localClaim = mock(LocalClaim.class);
        when(localClaim.getClaimURI()).thenReturn(claimUri);
        when(localClaim.getClaimProperty(ClaimConstants.MULTI_VALUED_PROPERTY)).thenReturn("false");

        return localClaim;
    }
}
