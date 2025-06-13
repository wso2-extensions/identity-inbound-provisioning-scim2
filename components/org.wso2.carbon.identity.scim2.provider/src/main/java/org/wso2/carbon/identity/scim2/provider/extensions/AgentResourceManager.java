
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import org.wso2.charon3.core.objects.ListedResource;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.objects.plainobjects.UsersGetResponse;
import org.wso2.charon3.core.protocol.ResponseCodeConstants;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.protocol.endpoints.AbstractResourceManager;
import org.wso2.charon3.core.protocol.endpoints.UserResourceManager;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon3.core.schema.SCIMResourceTypeSchema;
import org.wso2.charon3.core.utils.CopyUtil;
import org.wso2.charon3.core.utils.ResourceManagerUtil;
import org.wso2.charon3.core.utils.codeutils.Node;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 * Agent Resource Manager for handling SCIM2 agent operations.
 * 
 * <p>This class extends UserResourceManager to provide specialized agent management
 * functionality using the WSO2 Agent Schema (urn:scim:wso2:agent:schema). Agents are
 * treated as specialized user entities with additional agent-specific attributes.</p>
 * 
 * <p>Key features:</p>
 * <ul>
 *   <li>Agent creation with automatic password generation</li>
 *   <li>Domain-specific agent management (AGENT domain)</li>
 *   <li>Extended schema validation for agent-specific attributes</li>
 *   <li>SCIM 2.0 protocol compliance for agent operations</li>
 * </ul>
 * 
 * @since 7.2.0
 * @see UserResourceManager
 * @see org.wso2.charon3.core.protocol.endpoints.AbstractResourceManager
 */
public class AgentResourceManager extends UserResourceManager {

    /** Logger instance for this class. */
    private static final Logger logger = LoggerFactory.getLogger(AgentResourceManager.class);
     
    /** REST endpoint path for agent resources. */
    private static final String AGENT_ENDPOINT = "/Agents";
    
    /** Default domain name for agent user store operations. */
    protected static final String AGENT_STORE_DOMAIN = "AGENT";

    // Password generation constants for secure random password creation
    private static final String LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String NUMBERS = "0123456789";
    private static final String SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    private static final int DEFAULT_PASSWORD_LENGTH = 12;

    /** Secure random instance for cryptographically secure password generation. */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Constructs a new AgentResourceManager instance.
     * 
     * <p>Initializes the agent resource manager by calling the parent UserResourceManager
     * constructor and logging the initialization for debugging purposes.</p>
     */
    public AgentResourceManager() {
        super();
        logger.debug("AgentResourceManager initialized for agent management operations");
    }

    /**
     * Creates a new agent resource with SCIM 2.0 protocol compliance.
     * 
     * <p>This method handles the complete agent creation lifecycle including:</p>
     * <ul>
     *   <li>SCIM object decoding and validation</li>
     *   <li>Domain name prefix addition for agent store</li>
     *   <li>Automatic secure password generation if not provided</li>
     *   <li>Agent-specific schema validation</li>
     *   <li>Delegation to external agent manager for persistence</li>
     *   <li>Response encoding with proper headers</li>
     * </ul>
     * 
     * @param scimObjectString  Raw JSON string containing agent information in SCIM format
     * @param agentManager      Agent manager instance for handling agent persistence operations
     * @param attributes        Comma-separated list of attributes to include in response
     * @param excludeAttributes Comma-separated list of attributes to exclude from response
     * @return SCIM response containing created agent data with HTTP 201 status
     * @throws CharonException if SCIM processing fails
     * @throws BadRequestException if agent data is invalid
     * @throws ConflictException if agent already exists
     * @throws InternalErrorException if server processing fails
     */
    @Override
    public SCIMResponse create(String scimObjectString, UserManager agentManager, String attributes,
            String excludeAttributes) {

        try {
            logger.debug("Starting agent creation process");
            
            // Obtain the JSON encoder for response formatting
            JSONEncoder encoder = getEncoder();

            // Obtain the agent schema (extended user schema with agent-specific attributes)
            SCIMResourceTypeSchema schema = getAgentSchema(agentManager);

            // Decode the SCIM Agent object from the submitted JSON payload
            User agent = (User) getDecoder().decodeResource(scimObjectString, schema, new User());
            String requestedUsername = agent.getUserName();
            logger.debug("Successfully decoded agent object from request payload with username: {}", requestedUsername);

            // Add agent store domain name prefix to the agent username for proper user store routing
            if (agent.getUserName() != null && !agent.getUserName().contains("/")) {
                String originalUsername = agent.getUserName();
                agent.setUserName(AGENT_STORE_DOMAIN + UserCoreConstants.DOMAIN_SEPARATOR + originalUsername);
                logger.debug("Added domain prefix to agent username: {} -> {}", originalUsername, agent.getUserName());
            } else if (agent.getUserName() != null || agent.getUserName().contains("/")) {
                String error = "Agent username cannot contain domain name or be null.";
                logger.error("Invalid agent username format: {}", agent.getUserName());
                throw new BadRequestException(error);
            }

            // Auto-generate secure password if not provided in the request
            if (agent.getPassword() == null || agent.getPassword().trim().isEmpty()) {
                String generatedPassword = generateSecurePassword();
                agent.setPassword(generatedPassword);
                logger.debug("Auto-generated secure password for agent: {}", agent.getUserName());
            } else {
                logger.debug("Using provided password for agent: {}", agent.getUserName());
            }

            // Validate the created agent object with agent-specific validations
            validateCreatedAgent(agent, schema);
            logger.debug("Agent validation completed for username: {}", agent.getUserName());

            // Get the URIs of required attributes which must be given a value
            Map<String, Boolean> requiredAttributes = ResourceManagerUtil.getOnlyRequiredAttributesURIs(
                    (SCIMResourceTypeSchema) CopyUtil.deepCopy(schema), attributes, excludeAttributes);

            User createdAgent;

            if (agentManager != null) {
                // Handover the SCIM Agent object to the agent manager for persistence
                createdAgent = agentManager.createUser(agent, requiredAttributes);
                logger.debug("Agent creation delegated to agent manager for username: {}", agent.getUserName());
            } else {
                String error = "Provided agent manager handler is null.";
                logger.error("Agent manager is null for username: {}", agent.getUserName());
                throw new InternalErrorException(error);
            }

            // Encode the newly created SCIM agent object and prepare response headers
            String encodedAgent;
            Map<String, String> responseHeaders = new HashMap<String, String>();

            if (createdAgent != null) {
                // Create a deep copy of the agent object since we are going to modify it
                User copiedAgent = (User) CopyUtil.deepCopy(createdAgent);

                // Log agent creation success with ID
                String agentId = createdAgent.getId();
                logger.info("Successfully created agent with ID: {}", agentId);
                
                // Build agent location URL for response headers
                String agentLocationUrl = getResourceEndpointURL(AGENT_ENDPOINT) + "/" + agentId;
                logger.debug("Agent location URL generated: {} for agent ID: {}", agentLocationUrl, agentId);

                // Validate returned agent attributes against requested inclusion/exclusion
                validateReturnedAgentAttributes(copiedAgent, attributes, excludeAttributes);
                
                // Include the password in the response (this will be filtered out based on schema configuration)
                copiedAgent.setPassword(agent.getPassword());
                
                // Encode the agent object to JSON for response body
                encodedAgent = encoder.encodeSCIMObject(copiedAgent);

                // Add agent-specific location header
                responseHeaders.put(SCIMConstants.LOCATION_HEADER,
                        getResourceEndpointURL(AGENT_ENDPOINT) + "/" + createdAgent.getId());
                responseHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);

                logger.info("Successfully created agent with ID: {}", createdAgent.getId());
                // TODO Add an audit log entry for agent creation

            } else {
                String error = "Newly created Agent resource is null.";
                logger.error("Created agent is null");
                throw new InternalErrorException(error);
            }

            return new SCIMResponse(ResponseCodeConstants.CODE_CREATED, encodedAgent, responseHeaders);

        } catch (CharonException e) {
            if (e.getStatus() == -1) {
                e.setStatus(ResponseCodeConstants.CODE_INTERNAL_ERROR);
            }
            logger.error("CharonException in agent creation: {}", e.getMessage(), e);
            return AbstractResourceManager.encodeSCIMException(e);
        } catch (BadRequestException | ConflictException | InternalErrorException | NotFoundException
                | NotImplementedException | ForbiddenException e) {
            logger.error("Exception in agent creation: {}", e.getMessage(), e);
            return AbstractResourceManager.encodeSCIMException(e);
        }
    }

    /**
     * Retrieves the agent schema (extended user schema with agent-specific attributes).
     * 
     * <p>This method obtains the SCIM resource type schema that includes both the standard
     * user attributes and the WSO2 Agent Schema extensions. The schema is used for
     * validation and encoding/decoding of agent resources.</p>
     * 
     * <p>If an agent manager is provided, it will be used to retrieve any custom schema
     * extensions. Otherwise, the default user resource schema will be returned.</p>
     *
     * @param agentManager Agent manager instance that may provide custom schema extensions
     * @return Agent resource type schema including core user attributes and agent extensions
     * @throws BadRequestException if schema configuration is invalid
     * @throws NotImplementedException if schema functionality is not implemented
     * @throws CharonException if schema retrieval fails
     */
    private SCIMResourceTypeSchema getAgentSchema(UserManager agentManager)
            throws BadRequestException, NotImplementedException, CharonException {
        
        SCIMResourceTypeSchema schema;
        if (agentManager != null) {
            // Retrieve user schema with potential custom extensions from agent manager
            schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema(agentManager);
            logger.debug("Retrieved agent schema with custom extensions from agent manager");
        } else {
            // Fallback to standard user schema without custom extensions
            schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
            logger.debug("Retrieved standard agent schema without custom extensions");
        }
        return schema;
    }

    /**
     * Validates a created agent object with agent-specific validations.
     * 
     * <p>This method performs comprehensive validation of the agent object including:</p>
     * <ul>
     *   <li>Standard SCIM object validation (required attributes, data types, etc.)</li>
     *   <li>Agent-specific attribute validation (agentURL format, etc.)</li>
     *   <li>Schema compliance validation</li>
     * </ul>
     * 
     * @param agent The agent object to validate
     * @param schema The schema to validate against
     * @throws BadRequestException if agent data is invalid or missing required fields
     * @throws CharonException if validation processing fails
     * @throws NotFoundException if referenced resources are not found during validation
     */
    private void validateCreatedAgent(User agent, SCIMResourceTypeSchema schema)
            throws BadRequestException, CharonException, NotFoundException {
        // Perform standard SCIM validation plus agent-specific validations
        org.wso2.charon3.core.schema.ServerSideValidator.validateCreatedSCIMObject(agent, schema);
        String agentUsername = agent.getUserName();
        logger.debug("Agent validation completed for created agent with username: {}", agentUsername);
    }

    /**
     * Validates returned agent attributes against inclusion and exclusion criteria.
     * 
     * <p>This method ensures that the agent object being returned to the client
     * contains only the requested attributes and excludes any attributes that were
     * specifically excluded in the request.</p>
     * 
     * @param agent The agent object whose attributes need validation
     * @param attributes Comma-separated list of attributes to include (null means include all)
     * @param excludeAttributes Comma-separated list of attributes to exclude
     * @throws BadRequestException if attribute specification is invalid
     * @throws CharonException if attribute validation processing fails
     */
    private void validateReturnedAgentAttributes(User agent, String attributes, String excludeAttributes)
            throws BadRequestException, CharonException {
        
        // Validate returned agent attributes using SCIM server-side validator
        org.wso2.charon3.core.schema.ServerSideValidator.validateReturnedAttributes(agent, attributes,
                excludeAttributes);
        String agentId = agent.getId();
        String agentUsername = agent.getUserName();
        logger.debug("Agent returned attributes validation completed for agent ID: {} with username: {}", 
                     agentId, agentUsername);
    }

    /**
     * Generates a cryptographically secure random password for agent accounts.
     * 
     * <p>This method creates a secure password that meets standard password policy
     * requirements to ensure agent accounts are properly protected. The password
     * generation uses cryptographically secure random number generation.</p>
     * 
     * <p>Generated password characteristics:</p>
     * <ul>
     *   <li>At least one lowercase letter (a-z)</li>
     *   <li>At least one uppercase letter (A-Z)</li>
     *   <li>At least one numeric digit (0-9)</li>
     *   <li>At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)</li>
     *   <li>Total length of 12 characters (configurable via DEFAULT_PASSWORD_LENGTH)</li>
     *   <li>Character positions are shuffled to avoid predictable patterns</li>
     * </ul>
     * 
     * @return A randomly generated secure password meeting policy requirements
     */
    private String generateSecurePassword() {
        logger.debug("Generating secure password for agent account");
        
        StringBuilder password = new StringBuilder();
        String allChars = LOWERCASE_CHARS + UPPERCASE_CHARS + NUMBERS + SPECIAL_CHARS;

        // Ensure at least one character from each required category for policy compliance
        password.append(LOWERCASE_CHARS.charAt(SECURE_RANDOM.nextInt(LOWERCASE_CHARS.length())));
        password.append(UPPERCASE_CHARS.charAt(SECURE_RANDOM.nextInt(UPPERCASE_CHARS.length())));
        password.append(NUMBERS.charAt(SECURE_RANDOM.nextInt(NUMBERS.length())));
        password.append(SPECIAL_CHARS.charAt(SECURE_RANDOM.nextInt(SPECIAL_CHARS.length())));

        // Fill the remaining positions with random characters from all categories
        for (int i = 4; i < DEFAULT_PASSWORD_LENGTH; i++) {
            password.append(allChars.charAt(SECURE_RANDOM.nextInt(allChars.length())));
        }

        // Shuffle the password characters to avoid predictable patterns (e.g., all lowercase first)
        char[] passwordArray = password.toString().toCharArray();
        for (int i = passwordArray.length - 1; i > 0; i--) {
            int j = SECURE_RANDOM.nextInt(i + 1);
            char temp = passwordArray[i];
            passwordArray[i] = passwordArray[j];
            passwordArray[j] = temp;
        }

        String generatedPassword = new String(passwordArray);
        logger.debug("Successfully generated secure password with length: {} characters", generatedPassword.length());
        return generatedPassword;
    }
}