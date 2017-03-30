/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.inbound.provisioning.scim2.common.test.unit;


import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.inbound.provisioning.scim2.provider.resources.AbstractResource;
import org.wso2.carbon.identity.inbound.provisioning.scim2.provider.util.SCIMProviderConstants;

/**
 * Unit tests for Abstract Resource.
 */
public class AbstractResourceTests {

    @Test
    public void testIsValidOutputFormat() {
        AbstractResource abstractResource = new AbstractResource();
        boolean isValidOutput = abstractResource.isValidOutputFormat(SCIMProviderConstants.APPLICATION_JSON);
        Assert.assertEquals(isValidOutput, Boolean.TRUE.booleanValue(), "Failed in retrieving correct result.");
    }

    @Test
    public void testIsValidOutputFormatWithInvalidOutput() {
        AbstractResource abstractResource = new AbstractResource();
        boolean isValidOutput = abstractResource.isValidOutputFormat("****");
        Assert.assertEquals(isValidOutput, Boolean.FALSE.booleanValue(), "Failed in retrieving correct result.");
    }

    @Test
    public void testIsValidInputFormat() {
        AbstractResource abstractResource = new AbstractResource();
        boolean isValidOutput = abstractResource.isValidInputFormat(SCIMProviderConstants.APPLICATION_SCIM_JSON);
        Assert.assertEquals(isValidOutput, Boolean.TRUE.booleanValue(), "Failed in retrieving correct result.");
    }

    @Test
    public void testIsValidInputFormatWithInvalidInput() {
        AbstractResource abstractResource = new AbstractResource();
        boolean isValidOutput = abstractResource.isValidInputFormat("****");
        Assert.assertEquals(isValidOutput, Boolean.FALSE.booleanValue(), "Failed in retrieving correct result.");
    }
}
