/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.charon3.core.attributes.AbstractAttribute;
import org.wso2.charon3.core.attributes.Attribute;
import org.wso2.charon3.core.attributes.ComplexAttribute;
import org.wso2.charon3.core.attributes.DefaultAttributeFactory;
import org.wso2.charon3.core.attributes.MultiValuedAttribute;
import org.wso2.charon3.core.attributes.SimpleAttribute;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.NotFoundException;
import org.wso2.charon3.core.exceptions.NotImplementedException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.objects.AbstractSCIMObject;
import org.wso2.charon3.core.objects.Group;
import org.wso2.charon3.core.objects.SCIMObject;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.schema.AttributeSchema;
import org.wso2.charon3.core.schema.ResourceTypeSchema;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.schema.SCIMDefinitions;
import org.wso2.charon3.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon3.core.schema.SCIMSchemaDefinitions;
import org.wso2.charon3.core.utils.AttributeUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants.SCIM_COMPLEX_MULTIVALUED_ATTRIBUTE_SUPPORT_ENABLED;

/**
 * This class is responsible for converting SCIM attributes in a SCIM object to carbon claims and vice versa.
 */
public class AttributeMapper {

    public static final String ADVANCED_ATTRIBUTE_IDENTIFIER = "#";
    private static final Log log = LogFactory.getLog(AttributeMapper.class);

    /**
     * Return claims as a map of <ClaimUri (which is mapped to SCIM attribute uri),ClaimValue>.
     *
     * @param scimObject SCIM object.
     * @return A map of claims.
     */
    public static Map<String, String> getClaimsMap(AbstractSCIMObject scimObject) throws CharonException {

        Map<String, String> claimsMap = new HashMap<>();
        Map<String, Attribute> attributeList = scimObject.getAttributeList();
        for (Map.Entry<String, Attribute> attributeEntry : attributeList.entrySet()) {
            Attribute attribute = attributeEntry.getValue();
            // if the attribute is password, skip it
            if (SCIMConstants.UserSchemaConstants.PASSWORD.equals(attribute.getName())) {
                continue;
            }
            if (attribute instanceof SimpleAttribute) {
                setClaimsForSimpleAttribute(attribute, claimsMap);

            } else if (attribute instanceof MultiValuedAttribute) {
                setClaimsForMultivaluedAttribute(attribute, claimsMap);
            } else if (attribute instanceof ComplexAttribute) {
                /*
                NOTE: in carbon, we only support storing of type and value of a complex multi-valued attribute
                reading attributes list of the complex attribute.
                 */
                ComplexAttribute complexAttribute = (ComplexAttribute) attribute;
                Map<String, Attribute> attributes = null;
                if (complexAttribute.getSubAttributesList() != null &&
                        MapUtils.isNotEmpty(complexAttribute.getSubAttributesList())) {
                    attributes = complexAttribute.getSubAttributesList();
                }
                if (attributes != null) {
                    for (Attribute entry : attributes.values()) {
                        // if the attribute a simple attribute
                        if (entry instanceof SimpleAttribute) {
                            setClaimsForSimpleAttribute(entry, claimsMap);

                        } else if (entry instanceof MultiValuedAttribute) {
                            setClaimsForMultivaluedAttribute(entry, claimsMap);

                        } else if (entry instanceof ComplexAttribute) {
                            setClaimsForComplexAttribute(entry, claimsMap);
                        }
                    }
                }
            }
        }
        return claimsMap;
    }

    /**
     * Set claim mapping for simple attribute.
     *
     * @param attribute Target attribute.
     * @param claimsMap A map containing claims and corresponding values to be set for the target attribute.
     */
    private static void setClaimsForSimpleAttribute(Attribute attribute, Map<String, String> claimsMap)
            throws CharonException {

        String attributeURI = attribute.getURI();
        if (((SimpleAttribute) attribute).getValue() != null) {
            String attributeValue = AttributeUtil.getStringValueOfAttribute(
                    ((SimpleAttribute) attribute).getValue(), attribute.getType());
            // set attribute URI as the claim URI
            claimsMap.put(attributeURI, attributeValue);
        }
    }

    private static void setClaimsForSimpleSubAttributeOfMultivaluedComplexAttribute(String parentURI, Attribute
            attribute, Map<String, String> claimsMap, String type) throws CharonException {

        String attributeKey = attribute.getURI().replace(parentURI + ".", "");
        String attributeURI = parentURI + ADVANCED_ATTRIBUTE_IDENTIFIER + type + "." + attributeKey;
        if (((SimpleAttribute) attribute).getValue() != null) {
            String attributeValue = AttributeUtil.getStringValueOfAttribute(((SimpleAttribute) attribute).getValue(),
                    attribute.getType());
            // set attribute URI as the claim URI
            claimsMap.put(attributeURI, attributeValue);
        }
    }

    /**
     * Set claim mapping for multivalued attribute.
     *
     * @param attribute Target attribute.
     * @param claimsMap A map containing claims and corresponding values to be set for the target attribute.
     */
    private static void setClaimsForMultivaluedAttribute(Attribute attribute, Map<String, String> claimsMap)
            throws CharonException {

        MultiValuedAttribute multiValAttribute = (MultiValuedAttribute) attribute;
        // Get the URI of root attribute.
        String attributeURI = multiValAttribute.getURI();
        // Check if values are set as primitive values.
        List<Object> attributeValues = multiValAttribute.getAttributePrimitiveValues();
        if (CollectionUtils.isNotEmpty(attributeValues)) {
            String values = null;
            for (Object attributeValue : attributeValues) {
                if (values != null) {
                    values += FrameworkUtils.getMultiAttributeSeparator() + attributeValue;
                } else {
                    values = (String) attributeValue;
                }
            }
            claimsMap.put(attributeURI, values);
        }

        // check if values are set as complex values
        // NOTE: in carbon, we only support storing of type and
        // value of a multi-valued attribute
        List<Attribute> complexAttributeList = multiValAttribute.getAttributeValues();
        for (Attribute complexAttrib : complexAttributeList) {
            Map<String, Attribute> subAttributes =
                    ((ComplexAttribute) complexAttrib).getSubAttributesList();
            SimpleAttribute typeAttribute =
                    (SimpleAttribute) subAttributes.get(SCIMConstants.CommonSchemaConstants.TYPE);
            String valueAttriubuteURI;
            // construct attribute URI
            String typeValue = null;
            if (typeAttribute != null) {
                typeValue = (String) typeAttribute.getValue();
                valueAttriubuteURI = attributeURI + "." + typeValue;
            } else {
                valueAttriubuteURI = attributeURI;
            }
            SimpleAttribute valueAttribute = null;
            if (attribute.getName().equals(SCIMConstants.UserSchemaConstants.ADDRESSES)) {
                valueAttribute =
                        (SimpleAttribute) subAttributes.get(SCIMConstants.UserSchemaConstants.FORMATTED_ADDRESS);
            } else {
                valueAttribute =
                        (SimpleAttribute) subAttributes.get(SCIMConstants.CommonSchemaConstants.VALUE);
            }
            if (valueAttribute != null && valueAttribute.getValue() != null) {
                // Put it in claims.
                claimsMap.put(valueAttriubuteURI,
                        AttributeUtil.getStringValueOfAttribute(valueAttribute.getValue(), valueAttribute.getType()));

            }

            boolean isComplexMultivaluedSupportEnabled = Boolean.parseBoolean(IdentityUtil.getProperty
                    (SCIM_COMPLEX_MULTIVALUED_ATTRIBUTE_SUPPORT_ENABLED));
            if (isComplexMultivaluedSupportEnabled) {
                Map<String, Attribute> otherAttributes = new HashMap<>(subAttributes);
                otherAttributes.remove(SCIMConstants.CommonSchemaConstants.TYPE);
                otherAttributes.remove(SCIMConstants.CommonSchemaConstants.VALUE);
                for (Map.Entry<String, Attribute> entry : otherAttributes.entrySet()) {
                    if (entry.getValue() instanceof SimpleAttribute) {
                        setClaimsForSimpleSubAttributeOfMultivaluedComplexAttribute(attributeURI, entry.getValue(),
                                claimsMap, typeValue);
                    }
                }
            }
        }
    }

    /**
     * Set claim mapping for complex attribute.
     *
     * @param entry     Target attribute.
     * @param claimsMap A map containing claims and corresponding values to be set for the target attribute.
     */
    private static void setClaimsForComplexAttribute(Attribute entry, Map<String, String> claimsMap)
            throws CharonException {

        // Reading attributes list of the complex attribute.
        ComplexAttribute entryOfComplexAttribute = (ComplexAttribute) entry;
        Map<String, Attribute> entryAttributes;
        if (entryOfComplexAttribute.getSubAttributesList() != null &&
                MapUtils.isNotEmpty(entryOfComplexAttribute.getSubAttributesList())) {
            entryAttributes = entryOfComplexAttribute.getSubAttributesList();
            for (Attribute subEntry : entryAttributes.values()) {
                // attribute can only be simple attribute and that also in the extension schema only
                if (subEntry.getMultiValued()) {
                    setClaimsForMultivaluedAttribute(subEntry, claimsMap);
                } else {
                    setClaimsForSimpleAttribute(subEntry, claimsMap);
                }
            }
        }

    }

    public static SCIMObject constructSCIMObjectFromAttributes(UserManager userManager, Map<String, String> attributes,
                                                               int scimObjectType) throws CharonException,
            NotFoundException, BadRequestException{

        SCIMObject scimObject = null;
        switch (scimObjectType) {
            case SCIMCommonConstants.GROUP:
                scimObject = new Group();
                if (log.isDebugEnabled()) {
                    log.debug("Building Group Object");
                }
                break;
            case SCIMCommonConstants.USER:
                scimObject = new User();
                if (log.isDebugEnabled()) {
                    log.debug("Building User Object");
                }
                break;
            default:
                break;
        }
        for (Map.Entry<String, String> attributeEntry : attributes.entrySet()) {
            if (log.isDebugEnabled()) {
                log.debug("AttributeKey: " + attributeEntry.getKey() + " AttributeValue:" +
                        attributeEntry.getValue());
            }
            String attributeURI = attributeEntry.getKey();
            String[] attributeNames;

            if (attributeURI.contains(SCIMConstants.CORE_SCHEMA_URI)) {
                String[] attributeURIParts = attributeURI.split(":");
                String attributeNameString = attributeURIParts[attributeURIParts.length - 1];
                attributeNames = attributeNameString.split("\\.");
            } else {
                ArrayList<String> tempAttributeNames = new ArrayList<>();
                StringBuilder extensionURI = new StringBuilder();
                String[] attributeURIParts = attributeURI.split(":");
                for (int i = 0; i < attributeURIParts.length - 1; i++) {
                    extensionURI.append(":").append(attributeURIParts[i]);
                }
                String attributeNameString = attributeURIParts[attributeURIParts.length - 1];
                attributeNames = attributeNameString.split("\\.");
                tempAttributeNames.add(extensionURI.substring(1));

                tempAttributeNames.addAll(Arrays.asList(attributeNames));
                attributeNames = tempAttributeNames.toArray(attributeNames);
            }
            try {
                if (attributeNames.length == 1) {

                    constructSCIMObjectFromAttributesOfLevelOne(userManager, attributeEntry, scimObject, attributeNames,
                            scimObjectType);

                } else if (attributeNames.length == 2) {

                    constructSCIMObjectFromAttributesOfLevelTwo(userManager, attributeEntry, scimObject, attributeNames,
                            scimObjectType);

                } else if (attributeNames.length == 3) {

                    constructSCIMObjectFromAttributesOfLevelThree(userManager, attributeEntry, scimObject,
                            attributeNames, scimObjectType);
                }
            } catch (CharonException e) {
                log.error(e);
            }
        }
        return scimObject;
    }

    /**
     * construct the level one attributes like nickName.
     *
     * @param attributeEntry
     * @param scimObject
     * @param attributeNames
     * @param scimObjectType
     * @throws BadRequestException
     * @throws CharonException
     */
    public static void constructSCIMObjectFromAttributesOfLevelOne(UserManager userManager,
                                                                   Map.Entry<String, String> attributeEntry,
                                                                   SCIMObject scimObject, String[] attributeNames,
                                                                   int scimObjectType) throws BadRequestException,
            CharonException, NotFoundException {

        //get attribute schema
        AttributeSchema attributeSchema = getAttributeSchema(userManager, attributeEntry.getKey(), scimObjectType);
        if (attributeSchema != null) {
            //either simple valued or multi-valued with simple attributes
            if (attributeSchema.getMultiValued()) {
                //see whether multiple values are there
                String value = attributeEntry.getValue();
                Object[] values = value.split(",");

                // Check whether parent multi-valued attribute already exists.
                if (((AbstractSCIMObject) scimObject).isAttributeExist(attributeSchema.getName())) {
                    MultiValuedAttribute multiValuedAttribute = (MultiValuedAttribute) scimObject.getAttribute
                            (attributeSchema.getName());
                    // Set values.
                    multiValuedAttribute.setAttributePrimitiveValues(Arrays.asList(values));
                } else {
                    // Create attribute.
                    MultiValuedAttribute multiValuedAttribute = new MultiValuedAttribute(
                            attributeSchema.getName());
                    // Set values.
                    multiValuedAttribute.setAttributePrimitiveValues(Arrays.asList(values));
                    // Set attribute in scim object.
                    DefaultAttributeFactory.createAttribute(attributeSchema, multiValuedAttribute);
                    ((AbstractSCIMObject) scimObject).setAttribute(multiValuedAttribute);
                }

            } else {
                //convert attribute to relevant type
                Object attributeValueObject = AttributeUtil.getAttributeValueFromString(
                        attributeEntry.getValue(), attributeSchema.getType());
                //create attribute
                SimpleAttribute simpleAttribute = new SimpleAttribute(attributeNames[0],
                        attributeValueObject);
                DefaultAttributeFactory.createAttribute(attributeSchema, simpleAttribute);
                //set attribute in the SCIM object
                ((AbstractSCIMObject) scimObject).setAttribute(simpleAttribute);
            }
        }
    }
    /**
     * Construct the SCIM Object given the attribute URIs and attribute values of the object.
     *
     * @param attributes
     * @param scimObjectType
     * @return
     */
    public static SCIMObject constructSCIMObjectFromAttributes(Map<String, String> attributes,
                                                               int scimObjectType)
            throws CharonException, NotFoundException, BadRequestException {

        return constructSCIMObjectFromAttributes(null, attributes, scimObjectType);
    }

    /**
     * construct the level one attributes like nickName.
     *
     * @param attributeEntry
     * @param scimObject
     * @param attributeNames
     * @param scimObjectType
     * @throws BadRequestException
     * @throws CharonException
     */
    public static void constructSCIMObjectFromAttributesOfLevelOne(Map.Entry<String, String> attributeEntry,
                                                                   SCIMObject scimObject, String[] attributeNames,
                                                                   int scimObjectType)
            throws BadRequestException, CharonException, NotFoundException {
        constructSCIMObjectFromAttributesOfLevelOne(null, attributeEntry, scimObject, attributeNames, scimObjectType);
    }

    /**
     * construct the level two attributes like emails.value.
     *
     * @param userManager
     * @param attributeEntry
     * @param scimObject
     * @param attributeNames
     * @param scimObjectType
     * @throws BadRequestException
     * @throws CharonException
     * @throws NotFoundException
     */
    public static void constructSCIMObjectFromAttributesOfLevelTwo(UserManager userManager, Map.Entry<String, String> attributeEntry,
                                                                   SCIMObject scimObject, String[] attributeNames,
                                                                   int scimObjectType)
            throws BadRequestException, CharonException, NotFoundException {

        boolean isComplexMultivaluedSupportEnabled = Boolean.parseBoolean(IdentityUtil.getProperty
                (SCIM_COMPLEX_MULTIVALUED_ATTRIBUTE_SUPPORT_ENABLED));

        //get parent attribute name
        String parentAttributeName = attributeNames[0];
        //get parent attribute schema
        String parentAttributeURI = attributeEntry.getKey().replace("." + attributeNames[1], "");

        if (isComplexMultivaluedSupportEnabled && parentAttributeURI != null && parentAttributeURI.contains
                (ADVANCED_ATTRIBUTE_IDENTIFIER)) {
            String[] parentAttributeNames = parentAttributeURI.split(ADVANCED_ATTRIBUTE_IDENTIFIER);
            parentAttributeName = parentAttributeNames[0];
            AttributeSchema parentAttributeSchema = getAttributeSchema(userManager, parentAttributeName, scimObjectType);

            if (parentAttributeSchema == null) {
                if (log.isDebugEnabled()) {
                    log.debug("No Parent attribute schema found :" + parentAttributeName);
                }
                return;
            }

            String parentType = parentAttributeNames[1];
            String attributeName = attributeNames[1];

            SimpleAttribute typeSimpleAttribute = new SimpleAttribute(SCIMConstants.CommonSchemaConstants.TYPE,
                    parentType);

            String typeAttributeURI = parentAttributeName + "." + SCIMConstants.CommonSchemaConstants.TYPE;
            AttributeSchema typeAttributeSchema = getAttributeSchema(userManager, typeAttributeURI, scimObjectType);
            if (typeAttributeSchema == null) {
                if (log.isDebugEnabled()) {
                    log.debug("No Type attribute schema found :" + typeAttributeURI);
                }
                return;
            }
            DefaultAttributeFactory.createAttribute(typeAttributeSchema, typeSimpleAttribute);

            String valueAttributeURI = parentAttributeName + "." + attributeName;
            AttributeSchema valueSubAttributeSchema = getAttributeSchema(userManager, valueAttributeURI, scimObjectType);

            if (valueSubAttributeSchema == null) {
                if (log.isDebugEnabled()) {
                    log.debug("No Value attribute schema found :" + valueAttributeURI);
                }
                return;
            }

            SimpleAttribute valueSimpleAttribute = new SimpleAttribute(attributeName,
                    AttributeUtil.getAttributeValueFromString(attributeEntry.getValue(),
                            valueSubAttributeSchema.getType()));

            DefaultAttributeFactory.createAttribute(valueSubAttributeSchema, valueSimpleAttribute);

            Object type = SCIMCommonConstants.DEFAULT;
            Object value = SCIMCommonConstants.DEFAULT;

            if (attributeName != null) {
                type = attributeName;
            }
            if (valueSimpleAttribute.getValue() != null) {
                value = valueSimpleAttribute.getValue();
            }
            String complexName = parentAttributeName + "_" + type + "_" + value;
            ComplexAttribute complexAttribute = new ComplexAttribute(complexName);
            complexAttribute.setSubAttribute(typeSimpleAttribute);
            complexAttribute.setSubAttribute(valueSimpleAttribute);
            DefaultAttributeFactory.createAttribute(parentAttributeSchema, complexAttribute);

            // Check whether parent multivalued attribute already exists.
            if (((AbstractSCIMObject) scimObject).isAttributeExist(parentAttributeSchema.getName())) {
                // Create attribute value as complex value.
                updateComplexAttribute(scimObject, parentAttributeSchema.getName(), typeSimpleAttribute,
                        valueSimpleAttribute, complexAttribute);
            } else {
                // Create the attribute and set it in the scim object.
                MultiValuedAttribute multivaluedAttribute = new MultiValuedAttribute(parentAttributeSchema.getName());
                multivaluedAttribute.setAttributeValue(complexAttribute);
                DefaultAttributeFactory.createAttribute(parentAttributeSchema, multivaluedAttribute);
                ((AbstractSCIMObject) scimObject).setAttribute(multivaluedAttribute);
            }
        } else if (parentAttributeURI != null) {

            if (parentAttributeURI.equals(attributeEntry.getKey())) {
                parentAttributeURI = removeAttributeNameFromURI(attributeEntry.getKey(), attributeNames[1]);
            }
            AttributeSchema parentAttributeSchema = getAttributeSchema(userManager, parentAttributeURI, scimObjectType);

            if (parentAttributeSchema == null) {
                if (log.isDebugEnabled()) {
                    log.debug("No Parent attribute schema found for uri :" + parentAttributeURI);
                }
                return;
            }
                /*differentiate between sub attribute of Complex attribute and a Multivalued attribute
                with complex value*/
            if (parentAttributeSchema.getMultiValued()) {
                //get the value sub attribute
                String valueAttributeURI = attributeEntry.getKey().replace("." + attributeNames[1], "");
                AttributeSchema valueSubAttributeSchema = null;
                if (valueAttributeURI.equals(SCIMConstants.UserSchemaConstants.ADDRESSES_URI)) {
                    valueAttributeURI = valueAttributeURI + ".formatted";
                    valueSubAttributeSchema = getAttributeSchema(userManager, valueAttributeURI, scimObjectType);
                } else {
                    valueAttributeURI = valueAttributeURI + ".value";
                    valueSubAttributeSchema = getAttributeSchema(userManager, valueAttributeURI, scimObjectType);
                }
                //create map with complex value
                SimpleAttribute typeSimpleAttribute = new SimpleAttribute(SCIMConstants.CommonSchemaConstants.TYPE,
                        attributeNames[1]);

                String typeAttributeURI = attributeEntry.getKey().replace("." + attributeNames[1], "");
                typeAttributeURI = typeAttributeURI + ".type";
                AttributeSchema typeAttributeSchema = getAttributeSchema(userManager, typeAttributeURI, scimObjectType);
                DefaultAttributeFactory.createAttribute(typeAttributeSchema, typeSimpleAttribute);
                SimpleAttribute valueSimpleAttribute = new SimpleAttribute(valueSubAttributeSchema.getName(),
                        AttributeUtil.getAttributeValueFromString(attributeEntry.getValue(),
                                valueSubAttributeSchema.getType()));
                DefaultAttributeFactory.createAttribute(valueSubAttributeSchema, valueSimpleAttribute);

                //need to set a complex type value for multivalued attribute
                Object type = SCIMCommonConstants.DEFAULT;
                Object value = SCIMCommonConstants.DEFAULT;

                if (typeSimpleAttribute.getValue() != null) {
                    type = typeSimpleAttribute.getValue();
                }
                if (valueSimpleAttribute.getValue() != null) {
                    value = valueSimpleAttribute.getValue();
                }

                String complexName = parentAttributeName + "_" + value + "_" + type;

                ComplexAttribute complexAttribute = new ComplexAttribute(complexName);
                complexAttribute.setSubAttribute(typeSimpleAttribute);
                complexAttribute.setSubAttribute(valueSimpleAttribute);
                DefaultAttributeFactory.createAttribute(parentAttributeSchema, complexAttribute);

                //check whether parent multivalued attribute already exists
                if (((AbstractSCIMObject) scimObject).isAttributeExist(parentAttributeName)) {
                    //create attribute value as complex value
                    if (isComplexMultivaluedSupportEnabled) {
                        updateComplexAttribute(scimObject, parentAttributeName, typeSimpleAttribute,
                                valueSimpleAttribute, complexAttribute);
                    } else {
                        MultiValuedAttribute multiValuedAttribute = (MultiValuedAttribute) scimObject.getAttribute
                                (parentAttributeName);
                        multiValuedAttribute.setAttributeValue(complexAttribute);
                    }

                } else {
                    //create the attribute and set it in the scim object
                    MultiValuedAttribute multivaluedAttribute = new MultiValuedAttribute(
                            parentAttributeName);
                    multivaluedAttribute.setAttributeValue(complexAttribute);
                    DefaultAttributeFactory.createAttribute(parentAttributeSchema, multivaluedAttribute);
                    ((AbstractSCIMObject) scimObject).setAttribute(multivaluedAttribute);
                }
            } else {
                // Sub attribute of a complex attribute.
                AttributeSchema subAttributeSchema = getAttributeSchema(userManager, attributeEntry.getKey(), scimObjectType);
                AbstractAttribute attribute;

                if (subAttributeSchema.getMultiValued()) {
                    attribute = new MultiValuedAttribute(attributeNames[1]);
                    String[] stringAttributeValues = attributeEntry.getValue()
                            .split(FrameworkUtils.getMultiAttributeSeparator());
                    List<Object> attributeValues = new ArrayList<>();

                    for (String attributeValue : stringAttributeValues) {
                        attributeValues.add(AttributeUtil.getAttributeValueFromString(attributeValue,
                                subAttributeSchema.getType()));
                    }

                    ((MultiValuedAttribute) attribute).setAttributePrimitiveValues(attributeValues);
                    DefaultAttributeFactory.createAttribute(subAttributeSchema, attribute);
                } else {
                    attribute = new SimpleAttribute(attributeNames[1],
                            AttributeUtil.getAttributeValueFromString(attributeEntry.getValue(),
                                    subAttributeSchema.getType()));
                    DefaultAttributeFactory.createAttribute(subAttributeSchema, attribute);
                }

                // Check whether parent attribute exists.
                if (((AbstractSCIMObject) scimObject).isAttributeExist(parentAttributeSchema.getName())) {
                    ComplexAttribute complexAttribute =
                            (ComplexAttribute) scimObject.getAttribute(parentAttributeSchema.getName());
                    complexAttribute.setSubAttribute(attribute);
                } else {
                    // Create parent attribute and set sub attribute.
                    ComplexAttribute complexAttribute = new ComplexAttribute(parentAttributeSchema.getName());
                    complexAttribute.setSubAttribute(attribute);
                    DefaultAttributeFactory.createAttribute(parentAttributeSchema, complexAttribute);
                    ((AbstractSCIMObject) scimObject).setAttribute(complexAttribute);
                }

            }
        }
    }

    /**
     * construct the level two attributes like emails.value.
     *
     * @param attributeEntry
     * @param scimObject
     * @param attributeNames
     * @param scimObjectType
     * @throws BadRequestException
     * @throws CharonException
     * @throws NotFoundException
     */
    public static void constructSCIMObjectFromAttributesOfLevelTwo(Map.Entry<String, String> attributeEntry,
                                                                   SCIMObject scimObject, String[] attributeNames,
                                                                   int scimObjectType)
            throws BadRequestException, CharonException, NotFoundException {

        constructSCIMObjectFromAttributesOfLevelTwo(null, attributeEntry, scimObject, attributeNames, scimObjectType);
    }

    private static void updateComplexAttribute(SCIMObject scimObject, String parentAttributeName, SimpleAttribute
            typeSimpleAttribute, SimpleAttribute valueSimpleAttribute, ComplexAttribute complexAttribute)
            throws NotFoundException, CharonException {

        MultiValuedAttribute multiValuedAttribute = (MultiValuedAttribute) scimObject.getAttribute(parentAttributeName);
        boolean isExist = false;
        for (Attribute attribute : multiValuedAttribute.getAttributeValues()) {
            if (attribute.getType().equals(SCIMDefinitions.DataType.COMPLEX) && ((ComplexAttribute)
                    attribute).getSubAttributesList().get(SCIMConstants.CommonSchemaConstants.TYPE) != null) {

                Attribute subAttribute = ((ComplexAttribute)
                        attribute).getSubAttributesList().get(SCIMConstants.CommonSchemaConstants.TYPE);

                if (subAttribute != null && subAttribute.getType().equals(SCIMDefinitions.DataType.STRING)) {
                    String typeValue = ((SimpleAttribute) subAttribute).getStringValue();
                    if (typeValue != null && typeValue.equals(typeSimpleAttribute.getValue())) {
                        isExist = true;
                        ((ComplexAttribute) attribute).getSubAttributesList().put(valueSimpleAttribute.getName(),
                                valueSimpleAttribute);
                    }
                }

            }
        }
        if (!isExist) {
            multiValuedAttribute.setAttributeValue(complexAttribute);
        }
    }

    /**
     * construct the level three extension attributes like extensionSchema.manager.id.
     *
     * @param userManager
     * @param attributeEntry
     * @param scimObject
     * @param attributeNames
     * @param scimObjectType
     * @throws BadRequestException
     * @throws CharonException
     */
    public static void constructSCIMObjectFromAttributesOfLevelThree(UserManager userManager, Map.Entry<String, String> attributeEntry,
                                                                     SCIMObject scimObject, String[] attributeNames,
                                                                     int scimObjectType)
            throws BadRequestException, CharonException {
        String parentAttribute = attributeNames[0];
        //get immediate parent attribute name
        String immediateParentAttributeName = attributeNames[1];

        String subAttributeURI = attributeEntry.getKey().replace("." + attributeNames[2], "");
        AttributeSchema subAttributeSchema = getAttributeSchema(userManager, subAttributeURI, scimObjectType);

        String parentAttributeURI = removeAttributeNameFromURI(subAttributeURI, attributeNames[1]);
        AttributeSchema attributeSchema = getAttributeSchema(userManager, parentAttributeURI, scimObjectType);

        // Differentiate between sub attribute of Complex attribute and a Multivalued attribute with complex value.
        if (subAttributeSchema.getMultiValued()) {

            SimpleAttribute typeSimpleAttribute = new SimpleAttribute(SCIMConstants.CommonSchemaConstants.TYPE,
                    attributeNames[2]);
            AttributeSchema typeAttributeSchema = getAttributeSchema(userManager, subAttributeSchema.getURI()
                    + ".type", scimObjectType);
            if (typeAttributeSchema != null) {
                DefaultAttributeFactory.createAttribute(typeAttributeSchema, typeSimpleAttribute);
            }

            AttributeSchema valueAttributeSchema = getAttributeSchema(userManager, subAttributeSchema.getURI()
                    + ".value", scimObjectType);
            SimpleAttribute valueSimpleAttribute = null;
            if (valueAttributeSchema != null) {
                valueSimpleAttribute = new SimpleAttribute(SCIMConstants.CommonSchemaConstants.VALUE,
                        AttributeUtil.getAttributeValueFromString(attributeEntry.getValue(),
                                valueAttributeSchema.getType()));
                DefaultAttributeFactory.createAttribute(valueAttributeSchema, valueSimpleAttribute);
            }

            // Need to set a complex type value for multivalued attribute.
            Object type = SCIMCommonConstants.DEFAULT;
            Object value = SCIMCommonConstants.DEFAULT;

            if (typeSimpleAttribute.getValue() != null) {
                type = typeSimpleAttribute.getValue();
            }
            if (valueSimpleAttribute != null && valueSimpleAttribute.getValue()!= null) {
                value = valueSimpleAttribute.getValue();
            }
            String complexName = immediateParentAttributeName + "_" + value + "_" + type;
            ComplexAttribute complexAttribute = new ComplexAttribute(complexName);
            if (typeAttributeSchema != null) {
                complexAttribute.setSubAttribute(typeSimpleAttribute);
            }
            if (valueSimpleAttribute != null) {
                complexAttribute.setSubAttribute(valueSimpleAttribute);
            }
            DefaultAttributeFactory.createAttribute(subAttributeSchema, complexAttribute);

            ComplexAttribute extensionComplexAttribute;

            if (((AbstractSCIMObject) scimObject).isAttributeExist(parentAttribute)) {
                Attribute extensionAttribute = ((AbstractSCIMObject) scimObject).getAttribute(parentAttribute);
                extensionComplexAttribute = ((ComplexAttribute) extensionAttribute);
            } else {
                extensionComplexAttribute = new ComplexAttribute(parentAttribute);
                DefaultAttributeFactory.createAttribute(attributeSchema, extensionComplexAttribute);
                ((AbstractSCIMObject) scimObject).setAttribute(extensionComplexAttribute);
            }

            Map<String, Attribute> extensionSubAttributes = extensionComplexAttribute.getSubAttributesList();
            if (extensionSubAttributes.containsKey(attributeNames[1])) {
                //create attribute value as complex value
                MultiValuedAttribute multiValuedAttribute =
                        (MultiValuedAttribute) extensionSubAttributes.get(attributeNames[1]);
                multiValuedAttribute.setAttributeValue(complexAttribute);
            } else {
                //create the attribute and set it in the scim object
                MultiValuedAttribute multivaluedAttribute = new MultiValuedAttribute(attributeNames[1]);
                multivaluedAttribute.setAttributeValue(complexAttribute);
                DefaultAttributeFactory.createAttribute(subAttributeSchema, multivaluedAttribute);
                extensionComplexAttribute.setSubAttribute(multivaluedAttribute);
            }
        } else {

            AttributeSchema subSubAttributeSchema = getAttributeSchema(userManager, attributeEntry.getKey(), scimObjectType);
            AbstractAttribute attribute;

            if (subSubAttributeSchema.getMultiValued()) {
                attribute = new MultiValuedAttribute(attributeNames[2]);
                String[] stringAttributeValues = attributeEntry.getValue()
                        .split(FrameworkUtils.getMultiAttributeSeparator());
                List<Object> attributeValues = new ArrayList<>();

                for (String attributeValue : stringAttributeValues) {
                    attributeValues.add(AttributeUtil.getAttributeValueFromString(attributeValue,
                            subSubAttributeSchema.getType()));
                }

                ((MultiValuedAttribute) attribute).setAttributePrimitiveValues(attributeValues);
                DefaultAttributeFactory.createAttribute(subSubAttributeSchema, attribute);
            } else {
                attribute = new SimpleAttribute(attributeNames[2],
                        AttributeUtil.getAttributeValueFromString(attributeEntry.getValue(),
                                subSubAttributeSchema.getType()));
                DefaultAttributeFactory.createAttribute(subSubAttributeSchema, attribute);
            }

            // Check if the super parent exist.
            boolean superParentExist = ((AbstractSCIMObject) scimObject).isAttributeExist(attributeSchema.getName());
            if (superParentExist) {
                ComplexAttribute superParentAttribute = (ComplexAttribute) ((AbstractSCIMObject) scimObject)
                        .getAttribute(attributeSchema.getName());
                // Check if the immediate parent exist.
                boolean immediateParentExist = superParentAttribute.isSubAttributeExist(immediateParentAttributeName);
                if (immediateParentExist) {
                    // Both the parent and super parent exists.
                    ComplexAttribute immediateParentAttribute = (ComplexAttribute) superParentAttribute
                            .getSubAttribute(immediateParentAttributeName);
                    immediateParentAttribute.setSubAttribute(attribute);
                } else {
                    // Immediate parent does not exist.
                    ComplexAttribute immediateParentAttribute = new ComplexAttribute(immediateParentAttributeName);
                    immediateParentAttribute.setSubAttribute(attribute);
                    DefaultAttributeFactory.createAttribute(subAttributeSchema, immediateParentAttribute);
                    // Created the immediate parent and now set to super.
                    superParentAttribute.setSubAttribute(immediateParentAttribute);
                }
            } else {
                /*
                Now have to create both the super parent and immediate parent.
                Immediate first.
                 */
                ComplexAttribute immediateParentAttribute = new ComplexAttribute(immediateParentAttributeName);
                immediateParentAttribute.setSubAttribute(attribute);
                DefaultAttributeFactory.createAttribute(subAttributeSchema, immediateParentAttribute);
                // Now super parent.
                ComplexAttribute superParentAttribute = new ComplexAttribute(attributeSchema.getName());
                superParentAttribute.setSubAttribute(immediateParentAttribute);
                DefaultAttributeFactory.createAttribute(attributeSchema, superParentAttribute);
                // Now add the super to the scim object.
                ((AbstractSCIMObject) scimObject).setAttribute(superParentAttribute);
            }
        }
    }

    /**
     * construct the level three extension attributes like extensionSchema.manager.id.
     *
     * @param attributeEntry
     * @param scimObject
     * @param attributeNames
     * @param scimObjectType
     * @throws BadRequestException
     * @throws CharonException
     */
    public static void constructSCIMObjectFromAttributesOfLevelThree(Map.Entry<String, String> attributeEntry,
                                                                     SCIMObject scimObject, String[] attributeNames,
                                                                     int scimObjectType)
            throws BadRequestException, CharonException {

        constructSCIMObjectFromAttributesOfLevelThree(null, attributeEntry, scimObject, attributeNames, scimObjectType);
    }

    /**
     * Return the attribute schema for the asked attribute URI.
     *
     * @param attributeURI   URI of the SCIM attribute.
     * @param scimObjectType Type of the SCIM object.
     * @return Schema of the SCIM attribute belonging to the specified attributeURI and scimObjectType.
     */
    private static AttributeSchema getAttributeSchema(UserManager userManager, String attributeURI, int scimObjectType)
            throws BadRequestException, CharonException {

        ResourceTypeSchema resourceSchema = getResourceSchema(userManager, scimObjectType);
        if (resourceSchema != null) {
            List<AttributeSchema> attributeSchemas = resourceSchema.getAttributesList();
            for (AttributeSchema attributeSchema : attributeSchemas) {
                if (attributeURI.equals(attributeSchema.getURI())) {
                    return attributeSchema;
                }
                if (attributeSchema.getType().equals(SCIMDefinitions.DataType.COMPLEX)) {
                    if (attributeSchema.getMultiValued()) {
                        List<AttributeSchema> subAttributeSchemaList = attributeSchema.getSubAttributeSchemas();
                        for (AttributeSchema subAttributeSchema : subAttributeSchemaList) {
                            if (attributeURI.equals(subAttributeSchema.getURI())) {
                                return subAttributeSchema;
                            }
                        }
                    } else {
                        List<AttributeSchema> subAttributeSchemaList = attributeSchema.getSubAttributeSchemas();
                        for (AttributeSchema subAttributeSchema : subAttributeSchemaList) {
                            if (attributeURI.equals(subAttributeSchema.getURI())) {
                                return subAttributeSchema;
                            }
                            if (subAttributeSchema.getType().equals(SCIMDefinitions.DataType.COMPLEX)) {
                                // This is only valid for extension schema.
                                List<AttributeSchema> subSubAttributeSchemaList = subAttributeSchema
                                        .getSubAttributeSchemas();
                                for (AttributeSchema subSubAttributeSchema : subSubAttributeSchemaList) {
                                    if (attributeURI.equals(subSubAttributeSchema.getURI())) {
                                        return subSubAttributeSchema;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    /**
     * Return the corresponding resource type schema.
     *
     * @param scimObjectType SCIM object type.
     * @return Resource type schema of the given SCIM object type.
     */
    private static ResourceTypeSchema getResourceSchema(UserManager userManager, int scimObjectType)
            throws BadRequestException, CharonException {

        ResourceTypeSchema resourceSchema = null;
        switch (scimObjectType) {
            case 1:
                if (userManager != null) {
                    try {
                        resourceSchema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema(userManager);
                    } catch (NotImplementedException e) {
                        throw new CharonException("Error while getting user resource. GetUserResourceSchema is not " +
                                "implemented.");
                    }
                }
                if (resourceSchema == null) {
                    resourceSchema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
                }
                break;
            case 2:
                resourceSchema = SCIMSchemaDefinitions.SCIM_GROUP_SCHEMA;
                break;
            default:
                break;
        }
        return resourceSchema;
    }

    /**
     * Remove the attribute name from the URI.
     *
     * @param uri           Attribute URI.
     * @param attributeName Attribute name.
     * @return URI without the attribute name.
     */
    private static String removeAttributeNameFromURI(String uri, String attributeName) {

        if (StringUtils.isBlank(uri) || StringUtils.isBlank(attributeName)) {
            return uri;
        }

        String suffix = ":" + attributeName;
        int lastIndex = uri.lastIndexOf(suffix);
        if (lastIndex != -1 && lastIndex + suffix.length() == uri.length()) {
            return uri.substring(0, lastIndex);
        }

        return uri;
    }
}
