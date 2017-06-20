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

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.charon3.core.exceptions.CharonException;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Class responsible for building a programmatic representation of provisioning-config.xml.
 * Any application using this library can pass the file path
 * in expected format to get it parsed.
 */
public class SCIMConfigProcessor {

    private static SCIMConfigProcessor scimConfigProcessor = new SCIMConfigProcessor();

    //map to keep the properties values
    Map<String, String> properties = new HashMap<String, String>();
    //list to keep the authentication schemas
    List<AuthenticationSchema> authenticationSchemas = null;

    private Log logger = LogFactory.getLog(SCIMConfigProcessor.class);

    public Map<String, String> getProperties() {
        return properties;
    }

    public String getProperty(String property) {
        if (properties.get(property) != null) {
            return properties.get(property);
        }
        return null;
    }

    public List<AuthenticationSchema> getAuthenticationSchemas() {
        return authenticationSchemas;
    }

    public void buildConfigFromFile(String filePath) throws CharonException {
        try {
            InputStream inputStream = null;
            File provisioningConfig = new File(filePath);
            if (provisioningConfig.exists()) {
                inputStream = new FileInputStream(provisioningConfig);
                StAXOMBuilder staxOMBuilder = new StAXOMBuilder(inputStream);
                OMElement documentElement = staxOMBuilder.getDocumentElement();
                if (inputStream != null) {
                    inputStream.close();
                }
                buildConfigFromRootElement(documentElement);
            } else {
                throw new FileNotFoundException();
            }
        } catch (FileNotFoundException e) {
            throw new CharonException(SCIMCommonConstants.CHARON_CONFIG_NAME + "not found.");
        } catch (XMLStreamException e) {
            throw new CharonException("Error in building the configuration file: " +
                    SCIMCommonConstants.CHARON_CONFIG_NAME);
        } catch (IOException e) {
            throw new CharonException("Error in building the configuration file: " +
                    SCIMCommonConstants.CHARON_CONFIG_NAME);
        }
    }

    private void buildConfigFromRootElement(OMElement rootElement) {


        //read any properties defined.
        Iterator<OMElement> propertiesIterator = rootElement.getChildrenWithName(
                new QName(SCIMCommonConstants.ELEMENT_NAME_PROPERTY));

        while (propertiesIterator.hasNext()) {
            OMElement propertyElement = propertiesIterator.next();
            String propertyName = propertyElement.getAttributeValue(
                    new QName(SCIMCommonConstants.ATTRIBUTE_NAME_NAME));
            String propertyValue = propertyElement.getText();
            properties.put(propertyName, propertyValue);
        }

        OMElement scimAuthenticationSchemaElement = rootElement.getFirstChildWithName(
                new QName(SCIMCommonConstants.ELEMENT_NAME_AUTHENTICATION_SCHEMES));

        //iterate over the individual elements and create authentication schema map.
        Iterator<OMElement> authenticationSchemasIterator =
                scimAuthenticationSchemaElement.getChildrenWithName(new QName(SCIMCommonConstants.ELEMENT_NAME_SCHEMA));

        //build authentication schema map
        if (authenticationSchemasIterator != null) {
           authenticationSchemas  = buildAuthenticationSchemasMap(authenticationSchemasIterator);
        }
    }


    private List<AuthenticationSchema> buildAuthenticationSchemasMap
            (Iterator<OMElement> schemasIterator) {

        List<AuthenticationSchema> schemasList = new ArrayList<>();

        while (schemasIterator.hasNext()) {
            OMElement schemaElement = schemasIterator.next();
            AuthenticationSchema authenticationSchema = new AuthenticationSchema();
            Map<String, String> propertiesMap = new HashMap<String, String>();

            //read schema properties
            Iterator<OMElement> propertiesIterator = schemaElement.getChildrenWithName(
                    new QName(SCIMCommonConstants.ELEMENT_NAME_PROPERTY));
            while (propertiesIterator.hasNext()) {
                OMElement propertyElement = propertiesIterator.next();
                String propertyName = propertyElement.getAttributeValue(
                        new QName(SCIMCommonConstants.ATTRIBUTE_NAME_NAME));
                String propertyValue = propertyElement.getText();
                propertiesMap.put(propertyName, propertyValue);
            }
            authenticationSchema.setProperties(propertiesMap);
            schemasList.add(authenticationSchema);
        }

        return schemasList;
    }

    public static SCIMConfigProcessor getInstance() {
        return scimConfigProcessor;
    }
}

