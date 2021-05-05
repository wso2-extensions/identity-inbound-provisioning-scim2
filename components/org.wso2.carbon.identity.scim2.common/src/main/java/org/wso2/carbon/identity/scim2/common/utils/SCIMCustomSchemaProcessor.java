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

package org.wso2.carbon.identity.scim2.common.utils;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.charon3.core.config.SCIMConfigConstants;
import org.wso2.charon3.core.config.SCIMCustomAttribute;
import org.wso2.charon3.core.exceptions.CharonException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class SCIMCustomSchemaProcessor {

    private static final Log log = LogFactory.getLog(SCIMCustomSchemaProcessor.class);
    private String subAttributesOfCustomSchema = "";

    public List<SCIMCustomAttribute> getCustomAttributes(String tenantDomain, String customSchemaUri) throws IdentitySCIMException {

        try {
            Map<ExternalClaim, LocalClaim> customSchemaClaims =
                    SCIMCommonUtils.getMappedLocalClaimsForDialect(customSchemaUri, tenantDomain);
            return buildCustomSchemaAttributes(customSchemaClaims, customSchemaUri, tenantDomain);
        } catch (CharonException e) {
            throw new IdentitySCIMException("Error when reading the SCIM Schema information from the " + "persistence"
                    + " store.", e);
        }
    }

    private List<SCIMCustomAttribute> buildCustomSchemaAttributes(Map<ExternalClaim, LocalClaim> customSchemaClaims, String customSchemaUri, String tenantDomain) {

        List<SCIMCustomAttribute> SCIMCustomAttributes = new ArrayList<>();
        for (Map.Entry<ExternalClaim, LocalClaim> entry : customSchemaClaims.entrySet()){
            SCIMCustomAttribute SCIMCustomAttribute = new SCIMCustomAttribute();
            SCIMCustomAttribute.setAttributeUri(entry.getKey().getClaimURI());
            Map<String, String> attributeCharacteristics = new HashMap<>();
            for (Map.Entry<String, String> claimProperties : entry.getValue().getClaimProperties().entrySet()){
                String propertyName = modifyPropertyNamesToScimConvention(claimProperties.getKey());
                if(StringUtils.isNotBlank(propertyName)) {
                    String propertyValue = claimProperties.getValue();
                    attributeCharacteristics.put(propertyName, propertyValue);
                }
            }
            // Build subattributes for complex attributes.
            String subAttributes = buildSubAttributes(customSchemaClaims, attributeCharacteristics);
            attributeCharacteristics.put(SCIMConfigConstants.SUB_ATTRIBUTES, subAttributes);
            String attributeName = getAttributeName(entry.getKey().getClaimURI(), customSchemaUri, true);
            attributeCharacteristics.put(SCIMConfigConstants.ATTRIBUTE_NAME, attributeName);
            attributeCharacteristics.put(SCIMConfigConstants.ATTRIBUTE_URI, entry.getKey().getClaimURI());
            SCIMCustomAttribute.setProperties(attributeCharacteristics);
            SCIMCustomAttribute.setTenantId(IdentityTenantUtil.getTenantId(tenantDomain));

            SCIMCustomAttributes.add(SCIMCustomAttribute);
        }
        // Build custom schema configurations
        setCustomSchemaConfig(IdentityTenantUtil.getTenantId(tenantDomain), SCIMCustomAttributes, customSchemaUri);
        return SCIMCustomAttributes;
    }


    private String getAttributeName(String attributeUri, String customSchemaUri, boolean addAttributeToCustomSchema) {

        if (!attributeUri.startsWith(customSchemaUri)) {
            log.error("Attribute uri should start with custom schema uri");
            return null;
        } else {
            String attributeName = attributeUri.split(customSchemaUri + ":")[1];
            if (attributeName.contains(".")) {
                /*
                For sub attributed of a complex attribute, attributeUri will look like urn:sci.custom.schema:manager
                .displayName"
                 */
                attributeName = attributeName.split("\\.")[1];
            } else {
                // If it is a subattribute of a complex attribute, it should not be added as the
                // subattribute of the custom schema.
                if (addAttributeToCustomSchema) {
                    subAttributesOfCustomSchema += attributeName + " ";
                }
            }
            return attributeName;
        }
    }

    private String buildSubAttributes(Map<ExternalClaim, LocalClaim> customSchemaClaims,
                                      Map<String, String> attributeCharacteristics) {

        Map<String, String> localClaimsToCustomClaims = new HashMap<>();
        StringBuilder scimSubAttributesString = new StringBuilder();
        for (Map.Entry<ExternalClaim, LocalClaim> mappedClaims : customSchemaClaims.entrySet()) {
            String name = getAttributeName(mappedClaims.getKey().getClaimURI(),
                    mappedClaims.getKey().getClaimDialectURI(), false);
            localClaimsToCustomClaims.put(mappedClaims.getValue().getClaimURI(), name);
        }

        if ((StringUtils.isNotBlank(attributeCharacteristics.get(SCIMConfigConstants.DATA_TYPE))) && ("complex".equalsIgnoreCase(attributeCharacteristics.get(SCIMConfigConstants.DATA_TYPE)))) {
            String subAttributesLocalClaimsString = attributeCharacteristics.get(SCIMConfigConstants.SUB_ATTRIBUTES);
            if (StringUtils.isNotBlank(subAttributesLocalClaimsString) && !"null".equalsIgnoreCase(subAttributesLocalClaimsString)) {
                String[] subAttributesClaims = subAttributesLocalClaimsString.split(" ");
                for (String subAttributesClaim : subAttributesClaims) {
                    scimSubAttributesString.append(localClaimsToCustomClaims.get(subAttributesClaim)).append(" ");
                }
            }
        }
        return scimSubAttributesString.toString().toString();
    }

    /**
     * Set custom schema as an attribute and add all attributes as a subattribute of the custom schema.
     *
     * @param SCIMCustomAttributes
     * @param customSchemaUri
     */
    private void setCustomSchemaConfig(int tenantId, List<SCIMCustomAttribute> SCIMCustomAttributes,
                                       String customSchemaUri) {

        SCIMCustomAttribute scimCustomAttribute = new SCIMCustomAttribute();

        Map<String, String> properties = new HashMap<>();
        properties.put(SCIMConfigConstants.SUB_ATTRIBUTES, subAttributesOfCustomSchema);
        properties.put(SCIMConfigConstants.DATA_TYPE, "complex");
        properties.put(SCIMConfigConstants.ATTRIBUTE_URI, customSchemaUri);
        properties.put(SCIMConfigConstants.ATTRIBUTE_NAME, customSchemaUri);

        scimCustomAttribute.setProperties(properties);
        SCIMCustomAttributes.add(scimCustomAttribute);
    }

    /**
     * Modify the claim properties according to the scim schema convention.
     *
     * @param propertyName
     * @return
     */
    private String modifyPropertyNamesToScimConvention(String propertyName) {

        String scimPropertyName = null;
        if (StringUtils.equalsIgnoreCase(propertyName, SCIMConfigConstants.DATA_TYPE)) {
            return SCIMConfigConstants.DATA_TYPE;
        } else if (StringUtils.equalsIgnoreCase(propertyName, SCIMConfigConstants.MULTIVALUED)) {
            scimPropertyName = SCIMConfigConstants.MULTIVALUED;
        } else if (StringUtils.equalsIgnoreCase(propertyName, SCIMConfigConstants.DESCRIPTION)) {
            scimPropertyName = SCIMConfigConstants.DESCRIPTION;
        } else if (StringUtils.equalsIgnoreCase(propertyName, SCIMConfigConstants.REQUIRED)) {
            scimPropertyName = SCIMConfigConstants.REQUIRED;
        } else if (StringUtils.equalsIgnoreCase(propertyName, SCIMConfigConstants.CASE_EXACT)) {
            scimPropertyName = SCIMConfigConstants.CASE_EXACT;
        } else if (StringUtils.equalsIgnoreCase(propertyName, SCIMConfigConstants.MUTABILITY)) {
            scimPropertyName = SCIMConfigConstants.MUTABILITY;
        } else if (StringUtils.equalsIgnoreCase(propertyName, SCIMConfigConstants.RETURNED)) {
            scimPropertyName = SCIMConfigConstants.RETURNED;
        } else if (StringUtils.equalsIgnoreCase(propertyName, SCIMConfigConstants.UNIQUENESS)) {
            scimPropertyName = SCIMConfigConstants.UNIQUENESS;
        } else if (StringUtils.equalsIgnoreCase(propertyName, SCIMConfigConstants.SUB_ATTRIBUTES)) {
            scimPropertyName = SCIMConfigConstants.SUB_ATTRIBUTES;
        } else if (StringUtils.equalsIgnoreCase(propertyName, SCIMConfigConstants.REFERENCE_TYPES)) {
            scimPropertyName = SCIMConfigConstants.REFERENCE_TYPES;
        }
        return scimPropertyName;
    }
}