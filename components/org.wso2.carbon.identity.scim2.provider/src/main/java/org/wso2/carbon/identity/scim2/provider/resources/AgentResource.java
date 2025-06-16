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

package org.wso2.carbon.identity.scim2.provider.resources;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.jaxrs.designator.PATCH;
import org.wso2.carbon.identity.scim2.common.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.identity.scim2.provider.util.SCIMProviderConstants;
import org.wso2.carbon.identity.scim2.provider.util.SupportUtils;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.FormatNotSupportedException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.carbon.identity.scim2.provider.extensions.AgentResourceManager;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.scim2.provider.util.SupportUtils.buildCustomSchema;
import static org.wso2.carbon.identity.scim2.provider.util.SupportUtils.getTenantId;

/**
 * Agent Resource class for managing SCIM2 agent operations.
 * 
 * <p>
 * This class extends UserResource to provide specialized agent management
 * functionality using the WSO2 Agent Schema (urn:scim:wso2:agent:schema).
 * It handles CRUD operations for agent resources while maintaining
 * compatibility
 * with SCIM 2.0 protocol standards.
 * </p>
 * 
 * <p>
 * Key features:
 * </p>
 * <ul>
 * <li>Agent creation with custom schema validation</li>
 * <li>Agent listing with pagination and filtering</li>
 * <li>Support for both JSON and SCIM+JSON content types</li>
 * <li>Integration with WSO2 Identity Server's user management</li>
 * </ul>
 * 
 * @since 7.2.0
 * @see UserResource
 * @see AgentResourceManager
 */
@Path("/")
public class AgentResource extends UserResource {

    /** Logger instance for this class. */
    private static final Log LOG = LogFactory.getLog(AgentResource.class);

    /** Default domain name for agent resources. */
    private static final String AGENT_DOMAIN = "AGENT";

    /**
     * Create a new agent resource.
     * 
     * <p>
     * This method handles the creation of a new agent by accepting agent data
     * in JSON format and validating it against the WSO2 Agent Schema. The agent
     * data is processed through the AgentResourceManager which handles the SCIM
     * protocol compliance and persistence.
     * </p>
     * 
     * <p>
     * Content-Type and Accept headers are validated to ensure proper SCIM
     * protocol compliance. Both application/json and application/scim+json are
     * supported.
     * </p>
     * 
     * @param inputFormat        Request content type (must be application/json or
     *                           application/scim+json)
     * @param outputFormat       Response format preference
     * @param attribute          Comma-separated list of attributes to include in
     *                           response
     * @param excludedAttributes Comma-separated list of attributes to exclude from
     *                           response
     * @param resourceString     Agent data in JSON format conforming to SCIM schema
     * @return Response containing created agent details with appropriate HTTP
     *         status
     * @throws FormatNotSupportedException if content type or accept header is not
     *                                     supported
     * @throws CharonException             if agent creation fails due to validation
     *                                     or persistence errors
     */
    @Override
    @POST
    @Consumes({ MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON })
    @Produces({ MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON })
    public Response createUser(@HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
            @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
            @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
            @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
            String resourceString) {

        // Set agent flow context before operations
        LOG.debug("Setting thread local agent flow context to true for agent creation");
        SCIMCommonUtils.setThreadLocalIsAgentFlowContextThroughSCIM(true);
        
        try {
            // Validate content-type header for agent creation
            if (inputFormat == null) {
                String error = SCIMProviderConstants.CONTENT_TYPE + " not present in agent creation request header";
                throw new FormatNotSupportedException(error);
            }

            // Validate input format (content-type)
            if (!isValidInputFormat(inputFormat)) {
                String error = inputFormat + " is not supported for agent operations.";
                throw new FormatNotSupportedException(error);
            }

            // Validate output format (accept header)
            if (!isValidOutputFormat(outputFormat)) {
                String error = outputFormat + " is not supported for agent operations.";
                throw new FormatNotSupportedException(error);
            }

            // Obtain the agent manager from Identity SCIM Manager
            UserManager agentManager = IdentitySCIMManager.getInstance().getUserManager();

            // Build agent custom schema including WSO2 agent schema extensions
            buildAgentCustomSchema(agentManager, getTenantId());

            // Initialize agent resource manager for SCIM operations
            AgentResourceManager agentResourceManager = new AgentResourceManager();

            LOG.debug("Creating new agent with provided configuration");
            // Delegate to agent resource manager for actual creation
            SCIMResponse response = agentResourceManager.create(resourceString, agentManager,
                    attribute, excludedAttributes);

            // Build and return the HTTP response
            return SupportUtils.buildCreateUserResponse(response);

        } catch (CharonException e) {
            LOG.error("Error occurred while creating agent: " + e.getMessage(), e);
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            LOG.error("Format not supported for agent creation: " + e.getMessage(), e);
            return handleFormatNotSupportedException(e);
        } finally {
            // Unset agent flow context after operations
            LOG.debug("Unsetting thread local agent flow context after agent creation");
            SCIMCommonUtils.unsetThreadLocalIsAgentFlowContextThroughSCIM();
        }
    }

    /**
     * Override the getUser by ID method from UserResource to handle agent-specific retrieval.
     * 
     * @param id                 Agent ID to retrieve
     * @param outputFormat       Response format preference
     * @param attribute          Comma-separated list of attributes to include in response
     * @param excludedAttributes Comma-separated list of attributes to exclude from response
     * @return Response containing agent details or error response
     */
    @Override
    @GET
    @Path("{id}")
    @Produces({MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON})
    public Response getUser(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                            @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                            @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                            @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes) {

        // Set agent flow context before super call
        LOG.debug("Setting thread local agent flow context to true for agent retrieval by ID.");
        SCIMCommonUtils.setThreadLocalIsAgentFlowContextThroughSCIM(true);
        
        try {
            return super.getUser(id, outputFormat, attribute, excludedAttributes);
        } finally {
            // Unset agent flow context after super call
            LOG.debug("Unsetting thread local agent flow context after agent retrieval by ID.");
            SCIMCommonUtils.unsetThreadLocalIsAgentFlowContextThroughSCIM();
        }
    }

    /**
     * Override the getUser method from UserResource to handle agent-specific
     * listing.
     * 
     * <p>
     * This method intercepts the standard user listing endpoint and redirects it
     * to agent-specific listing functionality. The domain parameter is ignored for
     * agents since they are not domain-specific resources.
     * </p>
     * 
     * <p>
     * The method delegates to the static listAgents method which provides the
     * actual implementation for agent listing with proper SCIM protocol support.
     * </p>
     * 
     * @param format             Response format (application/json or
     *                           application/scim+json)
     * @param attribute          Comma-separated list of attributes to include in
     *                           response
     * @param excludedAttributes Comma-separated list of attributes to exclude from
     *                           response
     * @param filter             SCIM filter expression for agent filtering
     * @param startIndex         Pagination start index (1-based)
     * @param count              Maximum number of agents to return
     * @param sortBy             Attribute to sort by
     * @param sortOrder          Sort order (ascending or descending)
     * @param domainName         Domain name filter (ignored for agents)
     * @return Response containing list of agents matching the criteria
     */
    @Override
    @GET
    @Produces({ MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON })
    public Response getUser(@HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String format,
            @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
            @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
            @QueryParam(SCIMProviderConstants.FILTER) String filter,
            @QueryParam(SCIMProviderConstants.START_INDEX) Integer startIndex,
            @QueryParam(SCIMProviderConstants.COUNT) Integer count,
            @QueryParam(SCIMProviderConstants.SORT_BY) String sortBy,
            @QueryParam(SCIMProviderConstants.SORT_ORDER) String sortOrder,
            @QueryParam(SCIMProviderConstants.DOMAIN) String domainName) {

        // Set agent flow context before operations
        LOG.debug("Setting thread local agent flow context to true for agent listing");
        SCIMCommonUtils.setThreadLocalIsAgentFlowContextThroughSCIM(true);
        
        try {
            // Check if domain name parameter was provided and warn about its irrelevance
            if (domainName != null && !domainName.isEmpty()) {
                LOG.warn("Domain name parameter is not applicable for agents. Ignoring domain filter.");
            }

             domainName = AGENT_DOMAIN;
             return super.getUser(format, attribute, excludedAttributes, filter, startIndex, count, sortBy, sortOrder, domainName);
            // Delegate to static listAgents method for actual implementation
            // return AgentResource.listAgents(this, format, attribute, excludedAttributes, filter, startIndex, count, sortBy,
                    // sortOrder);
        } finally {
            // Unset agent flow context after operations
            LOG.debug("Unsetting thread local agent flow context after agent listing");
            SCIMCommonUtils.unsetThreadLocalIsAgentFlowContextThroughSCIM();
        }
    }

    /**
     * List all agents with optional filtering and pagination.
     * 
     * <p>
     * This static method provides the core implementation for agent listing
     * functionality. It supports SCIM 2.0 protocol features including:
     * </p>
     * <ul>
     * <li>Filtering using SCIM filter expressions</li>
     * <li>Pagination with startIndex and count parameters</li>
     * <li>Sorting by specified attributes</li>
     * <li>Attribute selection and exclusion</li>
     * </ul>
     * 
     * <p>
     * The method validates the output format, builds the agent custom schema,
     * and delegates to AgentResourceManager for the actual listing operation.
     * </p>
     * 
     * @param agentResource      The AgentResource instance for context and error
     *                           handling
     * @param format             Response format (application/json or
     *                           application/scim+json)
     * @param attribute          Comma-separated list of attributes to include in
     *                           response
     * @param excludedAttributes Comma-separated list of attributes to exclude from
     *                           response
     * @param filter             SCIM filter expression for agent filtering
     * @param startIndex         Pagination start index (1-based, defaults to 1)
     * @param count              Maximum number of agents to return (defaults to
     *                           server limit)
     * @param sortBy             Attribute to sort by (e.g., "userName", "created")
     * @param sortOrder          Sort order ("ascending" or "descending")
     * @return Response containing list of agents matching the criteria
     * @throws FormatNotSupportedException if the output format is not supported
     * @throws CharonException             if agent listing fails due to validation
     *                                     or retrieval errors
     */
    @GET
    @Produces({ MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON })
    public Response listAgents(AgentResource agentResource,
            @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String format,
            @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
            @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
            @QueryParam(SCIMProviderConstants.FILTER) String filter,
            @QueryParam(SCIMProviderConstants.START_INDEX) Integer startIndex,
            @QueryParam(SCIMProviderConstants.COUNT) Integer count,
            @QueryParam(SCIMProviderConstants.SORT_BY) String sortBy,
            @QueryParam(SCIMProviderConstants.SORT_ORDER) String sortOrder) {
        
        // Set default domain for agent operations

        return getUser(format, attribute, excludedAttributes, filter, startIndex, count, sortBy, sortOrder, AGENT_DOMAIN);
    }

    /**
     * Override the deleteUser method from UserResource to handle agent deletion.
     * 
     * @param id     Agent ID to delete
     * @param format Response format preference
     * @return Response indicating success or failure of deletion
     */
    @Override
    @DELETE
    @Path("{id}")
    public Response deleteUser(@PathParam(SCIMProviderConstants.ID) String id,
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String format) {

        // Set agent flow context before super call
        LOG.debug("Setting thread local agent flow context to true for agent deletion, ID.");
        SCIMCommonUtils.setThreadLocalIsAgentFlowContextThroughSCIM(true);
        
        try {
            return super.deleteUser(id, format);
        } finally {
            // Unset agent flow context after super call
            LOG.debug("Unsetting thread local agent flow context after agent deletion, ID.");
            SCIMCommonUtils.unsetThreadLocalIsAgentFlowContextThroughSCIM();
        }
    }

    /**
     * Override the getUsersByPost method from UserResource to handle agent search.
     * 
     * @param inputFormat    Request content type
     * @param outputFormat   Response format preference
     * @param resourceString Search criteria in JSON format
     * @return Response containing list of agents matching search criteria
     */
    @Override
    @POST
    @Path("/.search")
    @Produces({MediaType.APPLICATION_JSON, SCIMProviderConstants.APPLICATION_SCIM_JSON})
    public Response getUsersByPost(@HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                                   @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                                   String resourceString) {

        // Set agent flow context before super call
        LOG.debug("Setting thread local agent flow context to true for agent search");
        SCIMCommonUtils.setThreadLocalIsAgentFlowContextThroughSCIM(true);
        
        try {
            return super.getUsersByPost(inputFormat, outputFormat, resourceString);
        } finally {
            // Unset agent flow context after super call
            LOG.debug("Unsetting thread local agent flow context after agent search");
            SCIMCommonUtils.unsetThreadLocalIsAgentFlowContextThroughSCIM();
        }
    }

    /**
     * Override the updateUser method from UserResource to handle agent updates.
     * 
     * @param id                 Agent ID to update
     * @param inputFormat        Request content type
     * @param outputFormat       Response format preference
     * @param attribute          Comma-separated list of attributes to include in response
     * @param excludedAttributes Comma-separated list of attributes to exclude from response
     * @param resourceString     Updated agent data in JSON format
     * @return Response containing updated agent details or error response
     */
    @Override
    @PUT
    @Path("{id}")
    public Response updateUser(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                               @HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                               @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                               @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                               String resourceString) {

        // Set agent flow context before super call
        LOG.debug("Setting thread local agent flow context to true for agent update, ID.");
        SCIMCommonUtils.setThreadLocalIsAgentFlowContextThroughSCIM(true);
        
        try {
            return super.updateUser(id, inputFormat, outputFormat, attribute, excludedAttributes, resourceString);
        } finally {
            // Unset agent flow context after super call
            LOG.debug("Unsetting thread local agent flow context after agent update, ID.");
            SCIMCommonUtils.unsetThreadLocalIsAgentFlowContextThroughSCIM();
        }
    }

    /**
     * Override the patchUser method from UserResource to handle agent partial updates.
     * 
     * @param id                 Agent ID to update
     * @param inputFormat        Request content type
     * @param outputFormat       Response format preference
     * @param attribute          Comma-separated list of attributes to include in response
     * @param excludedAttributes Comma-separated list of attributes to exclude from response
     * @param resourceString     Patch operations in JSON format
     * @return Response containing updated agent details or error response
     */
    @Override
    @PATCH
    @Path("{id}")
    public Response patchUser(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                              @HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                              @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                              @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                              @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                              String resourceString) {

        // Set agent flow context before super call
        LOG.debug("Setting thread local agent flow context to true for agent patch, ID.");
        SCIMCommonUtils.setThreadLocalIsAgentFlowContextThroughSCIM(true);
        
        try {
            return super.patchUser(id, inputFormat, outputFormat, attribute, excludedAttributes, resourceString);
        } finally {
            // Unset agent flow context after super call
            LOG.debug("Unsetting thread local agent flow context after agent patch, ID.");
            SCIMCommonUtils.unsetThreadLocalIsAgentFlowContextThroughSCIM();
        }
    }

    /**
     * Build custom schema for agent operations including WSO2 agent schema
     * extensions.
     * 
     * <p>
     * This method ensures that the agent custom schema is properly built and
     * available for agent operations. It integrates the WSO2 Agent Schema
     * (urn:scim:wso2:agent:schema) with the standard SCIM schemas to provide
     * agent-specific attribute support.
     * </p>
     * 
     * <p>
     * The method calls the SupportUtils.buildCustomSchema() method which handles
     * the actual schema building process, including caching for performance.
     * </p>
     * 
     * @param agentManager Agent manager instance used for schema building
     *                     operations
     * @param tenantId     Tenant ID for multi-tenant schema support
     * @throws CharonException
     * @throws Exception       if schema building fails due to configuration or
     *                         validation errors
     */
    private void buildAgentCustomSchema(UserManager agentManager, int tenantId)
            throws CharonException {
        try {
            // Build custom schema with agent-specific extensions
            buildCustomSchema(agentManager, tenantId);
            LOG.debug("Agent custom schema built successfully for tenant: " + tenantId);
        } catch (Exception e) {
            LOG.error("Error building agent custom schema: " + e.getMessage(), e);
            throw new CharonException("Error while building scim custom schema", e);
        }
    }
}