/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.scim2.common.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.identity.scim2.common.handlers.SCIMClaimOperationEventHandler;
import org.wso2.charon3.core.attributes.MultiValuedAttribute;
import org.wso2.charon3.core.attributes.SimpleAttribute;
import org.wso2.charon3.core.encoder.JSONDecoder;
import org.wso2.charon3.core.encoder.JSONEncoder;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.InternalErrorException;
import org.wso2.charon3.core.exceptions.NotFoundException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.objects.AbstractSCIMObject;
import org.wso2.charon3.core.protocol.ResponseCodeConstants;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.protocol.endpoints.ResourceTypeResourceManager;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon3.core.schema.SCIMResourceTypeSchema;
import org.wso2.charon3.core.schema.ServerSideValidator;
import org.wso2.charon3.core.utils.CopyUtil;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils.isCustomSchemaEnabled;

/**
 * This is extended ResourceTypeResourceManager that handles /resourceTypes api.
 */
public class IdentityResourceTypeResourceManager extends ResourceTypeResourceManager {

    private static final Log log = LogFactory.getLog(IdentityResourceTypeResourceManager.class);


    /*
     * Retrieves a resource type
     *
     * @return SCIM response to be returned.
     */
    @Override
    public SCIMResponse get(String id, UserManager userManager, String attributes, String excludeAttributes) {

        return getResourceType();
    }

    /*
     * return RESOURCE_TYPE schema
     *
     * @return
     */
    private SCIMResponse getResourceType() {

        JSONEncoder encoder = null;
        try {
            //obtain the json encoder
            encoder = getEncoder();
            //obtain the json decoder
            JSONDecoder decoder = getDecoder();

            // get the service provider config schema
            SCIMResourceTypeSchema schema;
            String scimUserObjectString;
            if (isCustomSchemaEnabled()) {
                schema = SCIMResourceSchemaManager.getInstance().getResourceTypeResourceSchema();
                scimUserObjectString = encoder.buildUserResourceTypeJsonBody();
            } else {
                schema =
                        SCIMResourceSchemaManager.getInstance().getResourceTypeResourceSchemaWithoutMultiValuedSchemaExtensions();
                scimUserObjectString = buildUserResourceTypeJsonBody();
            }

            //create a string in json format for group resource type with relevant values
            String scimGroupObjectString = encoder.buildGroupResourceTypeJsonBody();
            //build the user abstract scim object
            AbstractSCIMObject userResourceTypeObject = (AbstractSCIMObject) decoder.decodeResource(
                    scimUserObjectString, schema, new AbstractSCIMObject());
            //add meta data
            userResourceTypeObject = ServerSideValidator.validateResourceTypeSCIMObject(userResourceTypeObject);
            //build the group abstract scim object
            AbstractSCIMObject groupResourceTypeObject = (AbstractSCIMObject) decoder.decodeResource(
                    scimGroupObjectString, schema, new AbstractSCIMObject());
            //add meta data
            groupResourceTypeObject = ServerSideValidator.validateResourceTypeSCIMObject(groupResourceTypeObject);
            //build the root abstract scim object
            AbstractSCIMObject resourceTypeObject = buildCombinedResourceType(userResourceTypeObject,
                    groupResourceTypeObject);
            //encode the newly created SCIM Resource Type object.
            String encodedObject;
            Map<String, String> responseHeaders = new HashMap<String, String>();

            if (resourceTypeObject != null) {
                //create a deep copy of the resource type object since we are going to change it.
                AbstractSCIMObject copiedObject = (AbstractSCIMObject) CopyUtil.deepCopy(resourceTypeObject);
                encodedObject = encoder.encodeSCIMObject(copiedObject);
                //add location header
                responseHeaders.put(SCIMConstants.LOCATION_HEADER, getResourceEndpointURL(
                        SCIMConstants.RESOURCE_TYPE_ENDPOINT));
                responseHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);

            } else {
                String error = "Newly created User resource is null.";
                throw new InternalErrorException(error);
            }
            //put the uri of the resource type object in the response header parameter.
            return new SCIMResponse(ResponseCodeConstants.CODE_OK,
                    encodedObject, responseHeaders);
        } catch (CharonException | BadRequestException | InternalErrorException | NotFoundException e) {
            return encodeSCIMException(e);
        } catch (JSONException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while building resourceType api response: ", e);
            }
            return null;
        }
    }

    /*
     * This combines the user and group resource type AbstractSCIMObjects and build a
     * one root AbstractSCIMObjects
     *
     * @param userObject
     * @param groupObject
     * @return
     * @throws CharonException
     */
    private AbstractSCIMObject buildCombinedResourceType(AbstractSCIMObject userObject, AbstractSCIMObject groupObject)
            throws CharonException {

        AbstractSCIMObject rootObject = new AbstractSCIMObject();
        MultiValuedAttribute multiValuedAttribute = new MultiValuedAttribute(
                SCIMConstants.ListedResourceSchemaConstants.RESOURCES);

        userObject.getSchemaList().clear();
        userObject.setSchema(SCIMConstants.RESOURCE_TYPE_SCHEMA_URI);
        multiValuedAttribute.setAttributePrimitiveValue(userObject);

        groupObject.getSchemaList().clear();
        groupObject.setSchema(SCIMConstants.RESOURCE_TYPE_SCHEMA_URI);
        multiValuedAttribute.setAttributePrimitiveValue(groupObject);

        rootObject.setAttribute(multiValuedAttribute);
        rootObject.setSchema(SCIMConstants.LISTED_RESOURCE_CORE_SCHEMA_URI);
        // Using a hard coded value of 2 since currently we only support two items in the list.
        SimpleAttribute totalResults = new SimpleAttribute(SCIMConstants.CommonSchemaConstants.TOTAL_RESULTS, 2);
        rootObject.setAttribute(totalResults);
        return rootObject;
    }

    /*
     *  Build the user resource type json representation.
     * @return
     */
    private String buildUserResourceTypeJsonBody() throws JSONException {

        JSONObject userResourceTypeObject = new JSONObject();
        userResourceTypeObject.put(SCIMConstants.CommonSchemaConstants.SCHEMAS, SCIMConstants.RESOURCE_TYPE_SCHEMA_URI);
        userResourceTypeObject.put(SCIMConstants.ResourceTypeSchemaConstants.ID, SCIMConstants.USER);
        userResourceTypeObject.put(SCIMConstants.ResourceTypeSchemaConstants.NAME, SCIMConstants.USER);
        userResourceTypeObject.put(SCIMConstants.ResourceTypeSchemaConstants.ENDPOINT, SCIMConstants.USER_ENDPOINT);
        userResourceTypeObject.put(SCIMConstants.ResourceTypeSchemaConstants.DESCRIPTION,
                SCIMConstants.ResourceTypeSchemaConstants.USER_ACCOUNT);
        userResourceTypeObject.put(SCIMConstants.ResourceTypeSchemaConstants.SCHEMA,
                SCIMConstants.USER_CORE_SCHEMA_URI);

        if (SCIMResourceSchemaManager.getInstance().isExtensionSet()) {
            JSONObject extensionSchemaObject = new JSONObject();
            extensionSchemaObject.put(SCIMConstants.ResourceTypeSchemaConstants.SCHEMA_EXTENSIONS_SCHEMA,
                    SCIMResourceSchemaManager.getInstance().getExtensionURI());
            extensionSchemaObject.put(SCIMConstants.ResourceTypeSchemaConstants.SCHEMA_EXTENSIONS_REQUIRED,
                    SCIMResourceSchemaManager.getInstance().getExtensionRequired());

            userResourceTypeObject.put(SCIMConstants.ResourceTypeSchemaConstants.SCHEMA_EXTENSIONS,
                    extensionSchemaObject);
        }
        return userResourceTypeObject.toString();
    }
}
