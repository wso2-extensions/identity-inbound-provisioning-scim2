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

package org.wso2.carbon.identity.scim2.provider.extensions;

import org.apache.commons.lang.StringUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.user.mgt.common.DefaultPasswordGenerator;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.charon3.core.encoder.JSONEncoder;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.ConflictException;
import org.wso2.charon3.core.exceptions.ForbiddenException;
import org.wso2.charon3.core.exceptions.InternalErrorException;
import org.wso2.charon3.core.exceptions.NotFoundException;
import org.wso2.charon3.core.exceptions.NotImplementedException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.objects.Agent;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.protocol.ResponseCodeConstants;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.protocol.endpoints.AbstractResourceManager;
import org.wso2.charon3.core.protocol.endpoints.UserResourceManager;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon3.core.schema.SCIMResourceTypeSchema;
import org.wso2.charon3.core.utils.CopyUtil;
import org.wso2.charon3.core.utils.ResourceManagerUtil;

import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.AGENTS_ENDPOINT;

import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Agent Resource Manager for handling SCIM2 agent operations.
 * 
 * <p>
 * This class extends UserResourceManager to provide specialized agent
 * management
 * functionality using the WSO2 Agent Schema (urn:scim:wso2:agent:schema).
 * Agents are
 * treated as specialized user entities with additional agent-specific
 * attributes.
 * </p>
 * 
 * <p>
 * Key features:
 * </p>
 * <ul>
 * <li>Agent creation with automatic password generation</li>
 * <li>Domain-specific agent management (AGENT domain)</li>
 * <li>Extended schema validation for agent-specific attributes</li>
 * <li>SCIM 2.0 protocol compliance for agent operations</li>
 * </ul>
 * 
 * @since 7.2.0
 * @see UserResourceManager
 * @see org.wso2.charon3.core.protocol.endpoints.AbstractResourceManager
 */
public class AgentResourceManager extends UserResourceManager {

    /** Logger instance for this class. */
    private static final Logger LOG = LoggerFactory.getLogger(AgentResourceManager.class);

    /**
     * Constructs a new AgentResourceManager instance.
     * 
     * <p>
     * Initializes the agent resource manager by calling the parent
     * UserResourceManager
     * constructor and logging the initialization for debugging purposes.
     * </p>
     */
    public AgentResourceManager() {
        super();
        LOG.debug("AgentResourceManager initialized for agent management operations");
    }

    /**
     * Creates a new agent resource with SCIM 2.0 protocol compliance.
     * 
     * <p>
     * This method handles the complete agent creation lifecycle including:
     * </p>
     * <ul>
     * <li>SCIM object decoding and validation</li>
     * <li>Domain name prefix addition for agent store</li>
     * <li>Automatic secure password generation if not provided</li>
     * <li>Agent-specific schema validation</li>
     * <li>Delegation to external agent manager for persistence</li>
     * <li>Response encoding with proper headers</li>
     * </ul>
     * 
     * @param scimObjectString  Raw JSON string containing agent information in SCIM
     *                          format
     * @param agentManager      Agent manager instance for handling agent
     *                          persistence operations
     * @param attributes        Comma-separated list of attributes to include in
     *                          response
     * @param excludeAttributes Comma-separated list of attributes to exclude from
     *                          response
     * @return SCIM response containing created agent data with HTTP 201 status
     * @throws CharonException        if SCIM processing fails
     * @throws BadRequestException    if agent data is invalid
     * @throws ConflictException      if agent already exists
     * @throws InternalErrorException if server processing fails
     */
    @Override
    public SCIMResponse create(String scimObjectString, UserManager agentManager, String attributes,
            String excludeAttributes) {

        try {
            LOG.debug("Starting agent creation process");

            // Obtain the JSON encoder for response formatting.
            JSONEncoder encoder = getEncoder();

            // Obtain the agent schema (extended user schema with agent-specific
            // attributes).
            SCIMResourceTypeSchema schema = getAgentSchema(agentManager);

            // Decode the SCIM Agent object from the submitted JSON payload.
            Agent agent = (Agent) getDecoder().decodeResource(scimObjectString, schema, new Agent());
            String requestedUsername = agent.getUserName();
            LOG.debug("Successfully decoded agent object from request payload with username: {}", requestedUsername);

            // Set isUserServingAgent value coming from the request to the thread-local.
            setIsUserServingAgent(scimObjectString);

            // Generate a unique ID for the agent as the username.
            if (StringUtils.isBlank(agent.getUsername())) {
                String agentID = UUID.randomUUID().toString();
                agent.setUserName(
                        IdentityUtil.getAgentIdentityUserstoreName() + UserCoreConstants.DOMAIN_SEPARATOR + agentID);
            } else if (!agent.getUsername().contains(UserCoreConstants.DOMAIN_SEPARATOR)) {
                String originalUsername = agent.getUserName();
                agent.setUserName(IdentityUtil.getAgentIdentityUserstoreName() + UserCoreConstants.DOMAIN_SEPARATOR
                        + originalUsername);
                LOG.debug("Added domain prefix to agent username: {} -> {}", originalUsername, agent.getUserName());
            } else if (agent.getUserName() != null && agent.getUserName().contains("/")) {
                String error = "Agent username cannot contain domain name or be null.";
                LOG.error("Invalid agent username format: {}", agent.getUserName());
                throw new BadRequestException(error);
            }

            // Auto-generate secure password if not provided in the request.
            if (agent.getPassword() == null || agent.getPassword().trim().isEmpty()) {
                DefaultPasswordGenerator passwordGenerator = new DefaultPasswordGenerator();
                String generatedPassword = new String(passwordGenerator.generatePassword())
                        .concat(new String(passwordGenerator.generatePassword()));
                agent.setPassword(generatedPassword);
                LOG.debug("Auto-generated secure password for agent: {}", agent.getUserName());
            } else {
                LOG.debug("Using provided password for agent: {}", agent.getUserName());
            }

            // Validate the created agent object with agent-specific validations.
            validateCreatedAgent(agent, schema);

            // Get the URIs of required attributes which must be given a value.
            Map<String, Boolean> requiredAttributes = ResourceManagerUtil.getOnlyRequiredAttributesURIs(
                    (SCIMResourceTypeSchema) CopyUtil.deepCopy(schema), attributes, excludeAttributes);

            User createdAgent;

            if (agentManager != null) {
                // Handover the SCIM Agent object to the agent manager for persistence.
                createdAgent = agentManager.createUser(agent, requiredAttributes);
                LOG.debug("Agent creation delegated to agent manager for name: {}", agent.getUserName());
            } else {
                String error = "Provided agent manager handler is null.";
                LOG.error("Agent manager is null for username: {}", agent.getUserName());
                throw new InternalErrorException(error);
            }

            // Encode the newly created SCIM agent object and prepare response headers.
            String encodedAgent;
            Map<String, String> responseHeaders = new HashMap<String, String>();

            if (createdAgent != null) {
                // Create a deep copy of the agent object since we are going to modify it.
                User copiedAgent = (User) CopyUtil.deepCopy(createdAgent);

                // Log agent creation success with ID.
                String agentId = createdAgent.getId();

                // Build agent location URL for response headers.
                String agentLocationUrl = getResourceEndpointURL(AGENTS_ENDPOINT) + "/" + agentId;
                LOG.debug("Agent location URL generated: {} for agent ID: {}", agentLocationUrl, agentId);

                // Validate returned agent attributes against requested inclusion/exclusion.
                validateReturnedAgentAttributes(copiedAgent, attributes, excludeAttributes);

                // Include the password in the response for agent creation.
                // Note: This is generally not recommended for security reasons, but done here
                // as the server generates a password for the agent and need to return it for later user.
                // The party onboarding the agent should handle this securely.
                copiedAgent.setPassword(agent.getPassword());

                // Encode the agent object to JSON for response body.
                encodedAgent = encoder.encodeSCIMObject(copiedAgent);

                // Add agent-specific location header.
                responseHeaders.put(SCIMConstants.LOCATION_HEADER,
                        getResourceEndpointURL(AGENTS_ENDPOINT) + "/" + createdAgent.getId());
                responseHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);

                LOG.info("Successfully created agent with ID: {}", createdAgent.getId());
                // TODO Add an audit log entry for agent creation.

            } else {
                String error = "Newly created Agent resource is null.";
                LOG.error(error);
                throw new InternalErrorException(error);
            }

            return new SCIMResponse(ResponseCodeConstants.CODE_CREATED, encodedAgent, responseHeaders);

        } catch (CharonException e) {
            if (e.getStatus() == -1) {
                e.setStatus(ResponseCodeConstants.CODE_INTERNAL_ERROR);
            }
            LOG.error("CharonException in agent creation: {}", e.getMessage(), e);
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (BadRequestException | ConflictException | InternalErrorException | NotFoundException
                | NotImplementedException | ForbiddenException e) {
            LOG.error("Exception in agent creation.", e);
            return AbstractResourceManager.encodeSCIMException(e);
        }
    }

    /**
     * Retrieves the agent schema (extended user schema with agent-specific
     * attributes).
     * 
     * <p>
     * This method obtains the SCIM resource type schema that includes both the
     * standard
     * user attributes and the WSO2 Agent Schema extensions. The schema is used for
     * validation and encoding/decoding of agent resources.
     * </p>
     * 
     * <p>
     * If an agent manager is provided, it will be used to retrieve any custom
     * schema
     * extensions. Otherwise, the default user resource schema will be returned.
     * </p>
     *
     * @param agentManager Agent manager instance that may provide custom schema
     *                     extensions
     * @return Agent resource type schema including core user attributes and agent
     *         extensions
     * @throws BadRequestException     if schema configuration is invalid
     * @throws NotImplementedException if schema functionality is not implemented
     * @throws CharonException         if schema retrieval fails
     */
    private SCIMResourceTypeSchema getAgentSchema(UserManager agentManager)
            throws BadRequestException, NotImplementedException, CharonException {

        // Check if agentIdentityIsEnabled is set to true in IdentityUtil.
        if (!IdentityUtil.isAgentIdentityEnabled()) {
            String error = "Agent identity management is not enabled in the system.";
            LOG.error(error);
            throw new NotImplementedException(error);
        }
        SCIMResourceTypeSchema schema;
        if (agentManager != null) {
            // Retrieve user schema with potential custom extensions from agent manager.
            schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema(agentManager);
            LOG.debug("Retrieved agent schema with custom extensions from agent manager");
        } else {
            // Fallback to standard user schema without custom extensions.
            schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
            LOG.debug("Retrieved standard agent schema without custom extensions");
        }
        return schema;
    }

    /**
     * Validates a created agent object with agent-specific validations.
     * 
     * <p>
     * This method performs comprehensive validation of the agent object including:
     * </p>
     * <ul>
     * <li>Standard SCIM object validation (required attributes, data types,
     * etc.)</li>
     * <li>Agent-specific attribute validation (agentURL format, etc.)</li>
     * <li>Schema compliance validation</li>
     * </ul>
     * 
     * @param agent  The agent object to validate
     * @param schema The schema to validate against
     * @throws BadRequestException if agent data is invalid or missing required
     *                             fields
     * @throws CharonException     if validation processing fails
     * @throws NotFoundException   if referenced resources are not found during
     *                             validation
     */
    private void validateCreatedAgent(User agent, SCIMResourceTypeSchema schema)
            throws BadRequestException, CharonException, NotFoundException {

        // Perform standard SCIM validation plus agent-specific validations.
        org.wso2.charon3.core.schema.ServerSideValidator.validateCreatedSCIMObject(agent, schema);
        String agentUsername = agent.getUserName();
        LOG.debug("Agent validation completed for created agent with username: {}", agentUsername);
    }

    /**
     * Validates returned agent attributes against inclusion and exclusion criteria.
     * 
     * <p>
     * This method ensures that the agent object being returned to the client
     * contains only the requested attributes and excludes any attributes that were
     * specifically excluded in the request.
     * </p>
     * 
     * @param agent             The agent object whose attributes need validation
     * @param attributes        Comma-separated list of attributes to include (null
     *                          means include all)
     * @param excludeAttributes Comma-separated list of attributes to exclude
     * @throws BadRequestException if attribute specification is invalid
     * @throws CharonException     if attribute validation processing fails
     */
    private void validateReturnedAgentAttributes(User agent, String attributes, String excludeAttributes)
            throws BadRequestException, CharonException {

        // Validate returned agent attributes using SCIM server-side validator.
        org.wso2.charon3.core.schema.ServerSideValidator.validateReturnedAttributes(agent, attributes,
                excludeAttributes);
        String agentId = agent.getId();
        String agentUsername = agent.getUserName();
        LOG.debug("Agent returned attributes validation completed for agent ID: {} with username: {}",
                agentId, agentUsername);
    }

    private void setIsUserServingAgent(String scimObjectString){
        try {
            JSONObject rawPayload = new JSONObject(scimObjectString);
            boolean isUserServingAgent = false;
            if (rawPayload.has(SCIMConstants.AGENT_SCHEMA_URI)) {
                JSONObject agentExtension = rawPayload.getJSONObject(SCIMConstants.AGENT_SCHEMA_URI);
                if (agentExtension.has("IsUserServingAgent")) {
                    isUserServingAgent = agentExtension.getBoolean("IsUserServingAgent");
                }
            }
            SCIMCommonUtils.setThreadLocalIsUserServingAgent(isUserServingAgent);
        } catch (Exception e) {
            LOG.warn("Failed to extract IsUserServingAgent flag, defaulting to false: {}", e.getMessage());
            SCIMCommonUtils.setThreadLocalIsUserServingAgent(false);
        }
    }
}
