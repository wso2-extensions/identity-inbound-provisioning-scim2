/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.scim2.common.cache;

import org.wso2.charon3.core.schema.AttributeSchema;

import java.io.Serializable;

/**
 * This stores list of custom attributes of SCIM2 agent schema.
 */
public class SCIMAgentAttributeSchemaCacheEntry implements Serializable {

    private static final long serialVersionUID = 3784848233717914595L;

    private final AttributeSchema attributeSchema;

    public SCIMAgentAttributeSchemaCacheEntry(AttributeSchema attributeSchema) {

        this.attributeSchema = attributeSchema;
    }

    public AttributeSchema getSCIMAgentAttributeSchema() {

        return attributeSchema;
    }
}
