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
import org.wso2.carbon.identity.claim.metadata.mgt.util.ClaimConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.charon3.core.attributes.SCIMCustomAttribute;
import org.wso2.charon3.core.config.SCIMConfigConstants;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.schema.SCIMDefinitions;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This process the local claims  and converts into scim2 custom schema attributes.
 */
public class SCIMCustomSchemaProcessor {

    private static final Log log = LogFactory.getLog(SCIMCustomSchemaProcessor.class);
    private String subAttributesOfCustomSchema = "";

    /**
     * This builds the custom schema attributes and returns list of custom attributes of the tenant.
     * @param tenantDomain TenantDomain
     * @param customSchemaUri CustomSchemaUri
     * @return List of custom attributes of the tenant.
     * @throws IdentitySCIMException
     */
    public List<SCIMCustomAttribute> getCustomAttributes(String tenantDomain, String customSchemaUri) throws IdentitySCIMException {

        try {
            Map<ExternalClaim, LocalClaim> customSchemaClaims =
                    SCIMCommonUtils.getMappedLocalClaimsForDialect(customSchemaUri, tenantDomain);
            return buildCustomSchemaAttributes(customSchemaClaims, customSchemaUri, tenantDomain);
        } catch (CharonException e) {
            throw new IdentitySCIMException("Error when building the SCIM2 Custom Schema information from the db" +
                    " for the tenant: " + tenantDomain, e);
        }
    }

    /**
     * This builds the custom schema attributes and returns the list of attributes belong to the custom schema.
     *
     * @param claims          Map of local claims and external claims that belong to custom schema dialect.
     * @param customSchemaUri CustomSchemaUri.
     * @param tenantDomain    Tenant domain.
     * @return List of custom attributes of the tenant.
     */
    private List<SCIMCustomAttribute> buildCustomSchemaAttributes(Map<ExternalClaim, LocalClaim> claims,
                                                                  String customSchemaUri, String tenantDomain) {

        List<SCIMCustomAttribute> SCIMCustomAttributes = new ArrayList<>();
        for (Map.Entry<ExternalClaim, LocalClaim> entry : claims.entrySet()){
            SCIMCustomAttribute SCIMCustomAttribute = new SCIMCustomAttribute();
            Map<String, String> attributeCharacteristics = new HashMap<>();
            for (Map.Entry<String, String> claimProperties : entry.getValue().getClaimProperties().entrySet()){
                String propertyName = modifyPropertyNamesToScimConvention(claimProperties.getKey());
                if(StringUtils.isNotBlank(propertyName)) {
                    String propertyValue = claimProperties.getValue();
                    attributeCharacteristics.put(propertyName, propertyValue);
                }
            }
            // Set mutabilty config.
            buildMutabilityConfig(attributeCharacteristics);
            // Build subattributes for complex attributes.
            String subAttributes = buildSubAttributes(claims, attributeCharacteristics);
            String attributeName = getAttributeName(entry.getKey().getClaimURI(), customSchemaUri, true);

            attributeCharacteristics.put(SCIMConfigConstants.SUB_ATTRIBUTES, subAttributes);
            attributeCharacteristics.put(SCIMConfigConstants.ATTRIBUTE_NAME, attributeName);
            attributeCharacteristics.put(SCIMConfigConstants.ATTRIBUTE_URI, entry.getKey().getClaimURI());
            SCIMCustomAttribute.setProperties(attributeCharacteristics);
            SCIMCustomAttributes.add(SCIMCustomAttribute);
        }
        // Build custom schema configurations
        setCustomSchemaConfig(SCIMCustomAttributes, customSchemaUri);
        return SCIMCustomAttributes;
    }


    /**
     * Derives the attribute Name using the attributeUri and  custom schema uri.
     *
     * @param attributeUri               AttributeUri.
     * @param customSchemaUri            CustomSchemaUri.
     * @param addAttributeToCustomSchema A boolean value to denote whether to add this attribute as a subattribute
     *                                   of the custom schema
     * @return Attribute Name.
     */
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

    /**
     * Builds subattributes for complex attributes
     *
     * @param customSchemaClaims       Map of local claim and external claim.
     * @param properties Map of all attribute properties.
     * @return Subattributes of a complex attribute.
     */
    private String buildSubAttributes(Map<ExternalClaim, LocalClaim> customSchemaClaims,
                                      Map<String, String> properties) {

        Map<String, String> localClaimsToAttributeNameMap = new HashMap<>();
        StringBuilder scimSubAttributesString = new StringBuilder();
        for (Map.Entry<ExternalClaim, LocalClaim> mappedClaims : customSchemaClaims.entrySet()) {
            // Do the mapping of local claim to attribute name.
            String name = getAttributeName(mappedClaims.getKey().getClaimURI(),
                    mappedClaims.getKey().getClaimDialectURI(), false);
            localClaimsToAttributeNameMap.put(mappedClaims.getValue().getClaimURI(), name);
        }

        /*
         * If the data type is complex and if the attribute has subattributes in local claim dialect with space
         * separated, split them and get the attribute name of the each localclaim.
         */
        if ((StringUtils.isNotBlank(properties.get(SCIMConfigConstants.DATA_TYPE))) && ("complex".equalsIgnoreCase(properties.get(SCIMConfigConstants.DATA_TYPE)))) {
            String subAttributesLocalClaimsString = properties.get(SCIMConfigConstants.SUB_ATTRIBUTES);
            if (StringUtils.isNotBlank(subAttributesLocalClaimsString) && !"null".equalsIgnoreCase(subAttributesLocalClaimsString)) {
                String[] subAttributes = subAttributesLocalClaimsString.split(" ");
                for (String localClaim : subAttributes) {
                    String attributeName = localClaimsToAttributeNameMap.get(localClaim);
                    if (StringUtils.isNotBlank(attributeName)) {
                        scimSubAttributesString.append(attributeName).append(" ");
                    } else {
                        // Local claim is added as a subattribute. But it does not have a mapped custom scim claim.
                        log.warn("Local claim: " + localClaim + " does not have a mapped custom claim");
                    }
                }
            }
        }
        return scimSubAttributesString.toString();
    }

    /**
     * Set custom schema as an attribute and add all attributes as a subattribute of the custom schema.
     *
     * @param SCIMCustomAttributes List of SCIMCustomAttributes.
     * @param customSchemaUri CustomSchemaUri.
     */
    private void setCustomSchemaConfig(List<SCIMCustomAttribute> SCIMCustomAttributes,
                                       String customSchemaUri) {

        SCIMCustomAttribute scimCustomAttribute = new SCIMCustomAttribute();
        Map<String, String> properties = new HashMap<>();
        properties.put(SCIMConfigConstants.SUB_ATTRIBUTES, subAttributesOfCustomSchema);
        properties.put(SCIMConfigConstants.DATA_TYPE, SCIMDefinitions.DataType.COMPLEX.name());
        properties.put(SCIMConfigConstants.ATTRIBUTE_URI, customSchemaUri);
        properties.put(SCIMConfigConstants.ATTRIBUTE_NAME, customSchemaUri);
        scimCustomAttribute.setProperties(properties);
        SCIMCustomAttributes.add(scimCustomAttribute);
    }

    /**
     * Modify the claim properties according to the scim schema convention.
     *
     * @param propertyName Property(name) of the attribute.
     * @return The scim2 corresponding name of the property.
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
        } else if(StringUtils.equalsIgnoreCase(propertyName, "ReadOnly")){
            scimPropertyName = "ReadOnly";
        }
        return scimPropertyName;
    }

    /**
     * Builds mutability property. If mutability property is defined, then it will take the higher precedennce.
     *
     * @param properties Map of all properties with their name and value.
     */
    private void buildMutabilityConfig(Map<String, String> properties) {

        if (StringUtils.isNotBlank(properties.get(ClaimConstants.READ_ONLY_PROPERTY)) &&
                StringUtils.isNotBlank(properties.get(SCIMConfigConstants.MUTABILITY))) {
            // If the claim properties have both readonly and mutability, give the precedence to mutability property.
            properties.remove(ClaimConstants.READ_ONLY_PROPERTY);
        } else if (StringUtils.isNotBlank(properties.get(ClaimConstants.READ_ONLY_PROPERTY))) {
            // If the claim properties have only readonly, set mutability property. .
            boolean isReadOnly = Boolean.parseBoolean(properties.get(ClaimConstants.READ_ONLY_PROPERTY));
            String mutability;
            if (isReadOnly) {
                mutability = SCIMDefinitions.Mutability.READ_ONLY.name();
            } else {
                mutability = SCIMDefinitions.Mutability.READ_WRITE.name();
            }
            properties.put(SCIMConfigConstants.MUTABILITY, mutability);
        }
    }
}
