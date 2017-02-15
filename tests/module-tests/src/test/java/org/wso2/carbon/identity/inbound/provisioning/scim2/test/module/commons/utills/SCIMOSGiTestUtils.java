/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.inbound.provisioning.scim2.test.module.commons.utills;

import org.ops4j.pax.exam.Option;
import org.wso2.carbon.osgi.test.util.CarbonSysPropConfiguration;
import org.wso2.carbon.osgi.test.util.OSGiTestConfigurationUtils;

import java.util.ArrayList;
import java.util.List;

import static org.ops4j.pax.exam.CoreOptions.mavenBundle;

/**
 * This class contains the utility methods for SCIM REST tests.
 */
public class SCIMOSGiTestUtils {

    /**
     * Returns the default list of PAX options needed for SCIM REST test.
     *
     * @return list of Options
     */
    public static List<Option> getDefaultSecurityPAXOptions() {

        List<Option> optionList = new ArrayList<>();

        optionList.add(mavenBundle()
                .groupId("org.ops4j.pax.logging")
                .artifactId("pax-logging-log4j2")
                .versionAsInProject());
        optionList.add(mavenBundle().
                artifactId("testng").
                groupId("org.testng").versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("net.minidev.wso2")
                .artifactId("json-smart")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("org.wso2.carbon.messaging")
                .artifactId("org.wso2.carbon.messaging")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("org.wso2.carbon.caching")
                .artifactId("org.wso2.carbon.caching")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("org.wso2.carbon.security.userstore")
                .artifactId("org.wso2.carbon.identity.mgt.store.connector.jdbc")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("org.wso2.carbon.identity.mgt")
                .artifactId("org.wso2.carbon.identity.mgt")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("commons-io.wso2")
                .artifactId("commons-io")
                .versionAsInProject());
        optionList.add(mavenBundle().
                groupId("commons-pool.wso2").
                artifactId("commons-pool").versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("org.apache.commons")
                .artifactId("commons-lang3")
                .versionAsInProject());
        optionList.add(mavenBundle().
                groupId("org.apache.servicemix.bundles").
                artifactId("org.apache.servicemix.bundles.commons-beanutils").versionAsInProject());
        optionList.add(mavenBundle().
                groupId("org.wso2.orbit.com.lmax").
                artifactId("disruptor").versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("com.zaxxer")
                .artifactId("HikariCP")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("com.h2database")
                .artifactId("h2")
                .versionAsInProject());
        optionList.add(mavenBundle().
                groupId("com.google.code.gson").
                artifactId("gson").versionAsInProject());
        optionList.add(mavenBundle().
                groupId("org.apache.commons").
                artifactId("commons-lang3").versionAsInProject());
        optionList.add(mavenBundle().
                groupId("org.wso2.carbon.datasources").
                artifactId("org.wso2.carbon.datasource.core").versionAsInProject());
        optionList.add(mavenBundle().
                groupId("org.wso2.carbon.jndi").
                artifactId("org.wso2.carbon.jndi")
                .versionAsInProject());
        optionList.add(mavenBundle().
                groupId("com.zaxxer").
                artifactId("HikariCP").versionAsInProject());
        optionList.add(mavenBundle().
                groupId("com.h2database").
                artifactId("h2").versionAsInProject());
        optionList.add(mavenBundle().
                groupId("org.wso2.msf4j").
                artifactId("msf4j-core").versionAsInProject());
        optionList.add(mavenBundle().
                groupId("org.wso2.carbon.transport").
                artifactId("org.wso2.carbon.transport.http.netty").versionAsInProject());
        optionList.add(mavenBundle().
                groupId("io.netty").
                artifactId("netty-transport").versionAsInProject());
        optionList.add(mavenBundle().
                groupId("io.netty").
                artifactId("netty-buffer").versionAsInProject());
        optionList.add(mavenBundle().
                groupId("io.netty").
                artifactId("netty-common").versionAsInProject());
        optionList.add(mavenBundle().
                groupId("io.netty").
                artifactId("netty-codec").versionAsInProject());
        optionList.add(mavenBundle().
                groupId("io.netty").
                artifactId("netty-codec-http").versionAsInProject());
        optionList.add(mavenBundle().
                groupId("io.netty").
                artifactId("netty-handler").versionAsInProject());
        optionList.add(mavenBundle().
                groupId("javax.ws.rs").
                artifactId("javax.ws.rs-api").versionAsInProject());
        optionList.add(mavenBundle().
                groupId("org.wso2.carbon.security.userstore").
                artifactId("org.wso2.carbon.identity.mgt.store.connector.jdbc").versionAsInProject());
        optionList.add(mavenBundle().
                groupId("org.wso2.carbon.identity.mgt").
                artifactId("org.wso2.carbon.identity.mgt")
                .versionAsInProject());
        optionList.add(mavenBundle().
                groupId("org.json").
                artifactId("json")
                .versionAsInProject());
        optionList.add(mavenBundle().
                groupId("org.wso2.carbon.identity.inbound.provisioning.scim2").
                artifactId("org.wso2.carbon.identity.inbound.provisioning.scim2.common")
                .versionAsInProject());
        optionList.add(mavenBundle().
                groupId("org.wso2.carbon.identity.inbound.provisioning.scim2").
                artifactId("org.wso2.carbon.identity.inbound.provisioning.scim2.provider")
                .versionAsInProject());
        optionList.add(mavenBundle().
                groupId("org.wso2.charon").
                artifactId("org.wso2.charon.core.v2")
                .versionAsInProject());
        optionList.add(mavenBundle().
                groupId("io.swagger").
                artifactId("swagger-annotations")
                .versionAsInProject());
        optionList.add(mavenBundle().
                groupId("org.wso2.msf4j").
                artifactId("jaxrs-delegates")
                .versionAsInProject().noStart());
        optionList.add(mavenBundle().
                groupId("org.wso2.carbon.identity.mgt").
                artifactId("org.wso2.carbon.identity.mgt.login.interceptor")
                .versionAsInProject());

        CarbonSysPropConfiguration sysPropConfiguration = new CarbonSysPropConfiguration();
        sysPropConfiguration.setCarbonHome(getCarbonHome());
        sysPropConfiguration.setServerKey("carbon-security");
        sysPropConfiguration.setServerName("WSO2 Carbon Security Server");
        sysPropConfiguration.setServerVersion("1.0.0");

        optionList = OSGiTestConfigurationUtils.getConfiguration(optionList, sysPropConfiguration);

        return optionList;
    }

    public static String getCarbonHome() {
        return System.getProperty("carbon.home");
    }
}

