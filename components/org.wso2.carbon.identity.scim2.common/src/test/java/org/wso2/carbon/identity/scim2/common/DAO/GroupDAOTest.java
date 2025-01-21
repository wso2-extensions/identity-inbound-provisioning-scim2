/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.scim2.common.DAO;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.mockito.MockitoAnnotations.initMocks;

public class GroupDAOTest {

    @Mock
    private Connection connection;

    @Mock
    private PreparedStatement mockedPreparedStatement;

    @Mock
    private ResultSet resultSet;

    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;
    private MockedStatic<SCIMCommonUtils> scimCommonUtils;

    @BeforeMethod
    public void setUp() {

        initMocks(this);
        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        scimCommonUtils = mockStatic(SCIMCommonUtils.class);
    }

    @AfterMethod
    public void tearDown() {

        identityDatabaseUtil.close();
        scimCommonUtils.close();
    }

    @Test
    public void testUpdateSCIMGroupAttributes() throws Exception {

        Map<String, String> attributes = new HashMap<>();
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.created", "2017-10-10T10:10:10Z");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.lastModified", "2017-10-10T10:10:10Z");

        when(IdentityDatabaseUtil.getDBConnection(true)).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(mockedPreparedStatement);
        when(mockedPreparedStatement.executeBatch()).thenReturn(new int[]{1});
        when(resultSet.next()).thenReturn(true);
        when(SCIMCommonUtils.getGroupNameWithDomain(anyString())).thenReturn("PRIMARY/GROUP_NAME");

        Connection mockedConnection2 = mock(Connection.class);
        PreparedStatement mockedPreparedStatement2 = mock(PreparedStatement.class);
        ResultSet mockedResultSet2 = mock(ResultSet.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(mockedConnection2);
        when(mockedConnection2.prepareStatement(anyString())).thenReturn(mockedPreparedStatement2);
        when(mockedPreparedStatement2.executeQuery()).thenReturn(mockedResultSet2);
        when(mockedResultSet2.next()).thenReturn(true);

        GroupDAO groupDAO = spy(new GroupDAO());
        doReturn(true).when(groupDAO).isExistingGroup(anyString(), anyInt());

        groupDAO.updateSCIMGroupAttributes(1, "GROUP_NAME", attributes);
        verify(mockedPreparedStatement, times(1)).executeBatch();
    }

    @Test(expectedExceptions = IdentitySCIMException.class,
            expectedExceptionsMessageRegExp = "Error when updating SCIM Attributes for the group: GROUP_NAME " +
                    "A Group with the same name doesn't exists.")
    public void testUpdateSCIMGroupAttributesWithNonExistingGroup() throws Exception {

        Map<String, String> attributes = new HashMap<>();
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.created", "2017-10-10T10:10:10Z");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.lastModified", "2017-10-10T10:10:10Z");

        when(IdentityDatabaseUtil.getDBConnection(true)).thenReturn(connection);
        when(SCIMCommonUtils.getGroupNameWithDomain(anyString())).thenReturn("PRIMARY/GROUP_NAME");

        GroupDAO groupDAO = spy(new GroupDAO());
        doReturn(false).when(groupDAO).isExistingGroup(anyString(), anyInt());
        groupDAO.updateSCIMGroupAttributes(1, "GROUP_NAME", attributes);
    }

    @Test(expectedExceptions = IdentitySCIMException.class,
            expectedExceptionsMessageRegExp = "Error when adding SCIM Attribute: nonExisting " +
                    "An attribute with the same name doesn't exists.")
    public void testUpdateSCIMGroupAttributesWithNonExistingAttributes() throws Exception {

        Map<String, String> attributes = new HashMap<>();
        attributes.put("nonExisting", "test-value");

        when(IdentityDatabaseUtil.getDBConnection(true)).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(mockedPreparedStatement);
        when(mockedPreparedStatement.executeBatch()).thenReturn(new int[]{1});
        when(resultSet.next()).thenReturn(true);
        when(SCIMCommonUtils.getGroupNameWithDomain(anyString())).thenReturn("PRIMARY/GROUP_NAME");

        Connection mockedConnection2 = mock(Connection.class);
        PreparedStatement mockedPreparedStatement2 = mock(PreparedStatement.class);
        ResultSet mockedResultSet2 = mock(ResultSet.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(mockedConnection2);
        when(mockedConnection2.prepareStatement(anyString())).thenReturn(mockedPreparedStatement2);
        when(mockedPreparedStatement2.executeQuery()).thenReturn(mockedResultSet2);
        when(mockedResultSet2.next()).thenReturn(false);

        GroupDAO groupDAO = spy(new GroupDAO());
        doReturn(true).when(groupDAO).isExistingGroup(anyString(), anyInt());
        groupDAO.updateSCIMGroupAttributes(1, "GROUP_NAME", attributes);
    }

    @Test(expectedExceptions = IdentitySCIMException.class,
            expectedExceptionsMessageRegExp = "Error updating the SCIM Group Attributes.")
    public void testUpdateSCIMGroupAttributesWithSQLException() throws Exception {

        Map<String, String> attributes = new HashMap<>();
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.created", "2017-10-10T10:10:10Z");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.lastModified", "2017-10-10T10:10:10Z");

        when(IdentityDatabaseUtil.getDBConnection(true)).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenThrow(new SQLException());
        when(SCIMCommonUtils.getGroupNameWithDomain(anyString())).thenReturn("PRIMARY/GROUP_NAME");

        GroupDAO groupDAO = spy(new GroupDAO());
        doReturn(true).when(groupDAO).isExistingGroup(anyString(), anyInt());
        groupDAO.updateSCIMGroupAttributes(1, "GROUP_NAME", attributes);
    }
}
