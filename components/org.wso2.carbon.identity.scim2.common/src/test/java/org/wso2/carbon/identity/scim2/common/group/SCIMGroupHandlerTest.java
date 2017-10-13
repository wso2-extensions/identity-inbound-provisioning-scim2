package org.wso2.carbon.identity.scim2.common.group;

import org.apache.commons.lang.StringUtils;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.*;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.scim2.common.DAO.GroupDAO;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.objects.Group;
import org.wso2.charon3.core.schema.SCIMConstants;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.text.SimpleDateFormat;
import java.util.*;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyMap;
import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.*;

@PrepareForTest({IdentityDatabaseUtil.class,StringUtils.class,SCIMCommonUtils.class,SCIMGroupHandler.class})
@PowerMockIgnore("java.sql.*")
public class SCIMGroupHandlerTest {

    @Mock
    private GroupDAO mockedGroupDAO;

    @Mock
    private Connection connection;

    @Mock
    private PreparedStatement mockedPreparedStatement;


    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);

    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    @Test
    public void testAddMandatoryAttributes() throws Exception {

        ResultSet resultSet = mock(ResultSet.class);
        mockStatic(SCIMCommonUtils.class);
        mockStatic(IdentityDatabaseUtil.class);

        when(SCIMCommonUtils.getSCIMGroupURL(anyString())).thenReturn("ID");
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(mockedPreparedStatement);
        when(mockedPreparedStatement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(false);
        when(mockedGroupDAO.isExistingGroup(SCIMCommonUtils.getGroupNameWithDomain("GROUP_NAME"),1)).thenReturn(false);

        SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(1);
        scimGroupHandler.addMandatoryAttributes(anyString());

    }

    @Test
    public void testGetGroupAttributesByName() throws Exception {
        Assert.assertNull(new SCIMGroupHandler(1).getGroupAttributesByName("managers"));
    }

    @Test
    public void testGetGroupAttributesById() throws Exception {
        Assert.assertNull(new SCIMGroupHandler(1).getGroupAttributesById("1"));
    }

    @Test
    public void testCreateSCIMAttributes() throws Exception {
        ResultSet resultSet = mock(ResultSet.class);

        mockStatic(IdentityDatabaseUtil.class);
        mockStatic(SCIMCommonUtils.class);

        Group group = new Group();

        Date date = new Date();
        group.setCreatedDate(date);
        group.setLastModified(date);
        group.setLocation("LOCATION_URI");

        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(mockedPreparedStatement);
        when(mockedPreparedStatement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(false);
        when(mockedGroupDAO.isExistingGroup(SCIMCommonUtils.getGroupNameWithDomain("NON_EXISTANT_GROUP_NAME"),1)).thenReturn(false);

        SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(1);
        scimGroupHandler.createSCIMAttributes(group);


    }

    @Test(expectedExceptions = IdentitySCIMException.class)
    public void testCreateSCIMAttributesExceptions() throws Exception{
        mockStatic(IdentityDatabaseUtil.class);
        ResultSet resultSet = mock(ResultSet.class);
        Group group =  new Group();
        Date date = new Date();
        group.setCreatedDate(date);
        group.setLastModified(date);
        group.setLocation("LOCATION_URI");

        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(mockedPreparedStatement);
        when(mockedPreparedStatement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(true);
        when(mockedGroupDAO.isExistingGroup(SCIMCommonUtils.getGroupNameWithDomain("ALREADY_EXISTANT_GROUP_NAME"),1)).thenReturn(true);

        SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(1);
        scimGroupHandler.createSCIMAttributes(group);

    }

    @Test
    public void testGetGroupName() throws Exception {

        ResultSet resultSet = mock(ResultSet.class);
        mockStatic(IdentityDatabaseUtil.class);
        mockStatic(StringUtils.class);
        mockStatic(SCIMCommonUtils.class);

        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(mockedPreparedStatement);
        when(StringUtils.isNotEmpty(anyString())).thenReturn(true);
        when(SCIMCommonUtils.getPrimaryFreeGroupName(anyString())).thenReturn("directors");
        when(mockedPreparedStatement.executeQuery()).thenReturn(resultSet);
        when(mockedGroupDAO.getGroupNameById(1,"5")).thenReturn("directors");

        Assert.assertEquals(new SCIMGroupHandler(1).getGroupName("5"),"directors");

        when(StringUtils.isNotEmpty(anyString())).thenReturn(false);
        Assert.assertNull(new SCIMGroupHandler(1).getGroupName("NON_EXISITNG_GROUP_NAME"));

    }

    @Test
    public void testGetGroupId() throws Exception {

        Assert.assertNull(new SCIMGroupHandler(1).getGroupId("directors"));
    }

    @Test
    public void testGetGroupWithAttributes() throws Exception {
        Group group = new Group();
        ResultSet resultSet = mock(ResultSet.class);
        Map<String,String> attributes = new HashMap<String,String>();

        Date date = new Date(2017,10,10,10,10,10);

        attributes.put("urn:ietf:params:scim:schemas:core:2.0:id","100");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.created",date.toString());
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.lastModified",date.toString());
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.location","colombo");



        mockStatic(IdentityDatabaseUtil.class);
        mockStatic(StringUtils.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(mockedPreparedStatement);
        when(resultSet.next()).thenReturn(false);
        when(mockedPreparedStatement.executeQuery()).thenReturn(resultSet);

        when(mockedGroupDAO.isExistingGroup("NON_EXISTING_GROUP_NAME",1)).thenReturn(false);
        Assert.assertEquals(new SCIMGroupHandler(1).getGroupWithAttributes(group,"NON_EXISTING_GROUP_NAME"),group);

    }

   @Test
    public void testGetGroupWithAttributesSecondScenario() throws Exception {
        Group group = new Group();
        ResultSet resultSet = mock(ResultSet.class);


       Date today = Calendar.getInstance().getTime();
       SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");


        Map<String,String> attributes = new HashMap<String,String>();
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:id","100");
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.created",formatter.format(today));
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.lastModified",formatter.format(today));
        attributes.put("urn:ietf:params:scim:schemas:core:2.0:meta.location",null);

        mockStatic(IdentityDatabaseUtil.class);
        mockStatic(StringUtils.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(mockedPreparedStatement);
        when(resultSet.next()).thenReturn(true);
        when(mockedPreparedStatement.executeQuery()).thenReturn(resultSet);

        when(mockedGroupDAO.isExistingGroup("EXISTING_GROUP_NAME",1)).thenReturn(true);

        whenNew(GroupDAO.class).withNoArguments().thenReturn(mockedGroupDAO);
        when(mockedGroupDAO.getSCIMGroupAttributes(anyInt(),anyString())).thenReturn(attributes);
        when(StringUtils.isNotEmpty(resultSet.getString(anyInt()))).thenReturn(true);

        Assert.assertEquals(new SCIMGroupHandler(1).getGroupWithAttributes(group,"EXISTING_GROUP_NAME"),group);

    }


    @Test
    public void testIsGroupExisting() throws Exception {

       ResultSet resultSet = mock(ResultSet.class);
       mockStatic(IdentityDatabaseUtil.class);
       when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
       when(connection.prepareStatement(anyString())).thenReturn(mockedPreparedStatement);
       when(resultSet.next()).thenReturn(true);
       when(mockedPreparedStatement.executeQuery()).thenReturn(resultSet);
       when(mockedGroupDAO.isExistingGroup("managers",1)).thenReturn(true);
       Assert.assertTrue(new SCIMGroupHandler(1).isGroupExisting("managers"));

       when(resultSet.next()).thenReturn(false);
       when(mockedGroupDAO.isExistingGroup("directors",1)).thenReturn(false);
       Assert.assertEquals(new SCIMGroupHandler(1).isGroupExisting("directors"),false);

    }

    @Test
    public void testDeleteGroupAttributes() throws Exception {
        ResultSet resultSet = mock(ResultSet.class);
        mockStatic(IdentityDatabaseUtil.class);

        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(mockedPreparedStatement);
        when(mockedPreparedStatement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(true);

        SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(1);
        scimGroupHandler.deleteGroupAttributes("GROUP_DELETABLE");

    }

    @Test
    public void testUpdateRoleName() throws Exception {

        ResultSet resultSet = mock(ResultSet.class);
        mockStatic(IdentityDatabaseUtil.class);

        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(mockedPreparedStatement);
        when(mockedPreparedStatement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(true);
        when(mockedGroupDAO.isExistingGroup("EXISTENT_ROLE_NAME",1)).thenReturn(true);

        SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(1);
        scimGroupHandler.updateRoleName("EXISTENT_ROLE_NAME","NEW_ROLE_NAME");
    }

    @Test(expectedExceptions = IdentitySCIMException.class)
    public void testUpdateRoleNameException() throws Exception{
        ResultSet resultSet = mock(ResultSet.class);
        mockStatic(IdentityDatabaseUtil.class);

        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(mockedPreparedStatement);
        when(mockedPreparedStatement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(false);
        when(mockedGroupDAO.isExistingGroup("NON_EXISTENT_ROLE_NAME",1)).thenReturn(false);

        SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(1);
        scimGroupHandler.updateRoleName("NON_EXISTENT_ROLE_NAME","NEW_ROLE_NAME");
    }

    @Test
    public void testListSCIMRoles() throws Exception {
        Set<String> groups = mock(HashSet.class);
        ResultSet resultSet = mock(ResultSet.class);
        mockStatic(IdentityDatabaseUtil.class);
        
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(mockedPreparedStatement);
        when(resultSet.next()).thenReturn(false);
        when(mockedPreparedStatement.executeQuery()).thenReturn(resultSet);
        when(mockedGroupDAO.listSCIMGroups()).thenReturn(groups);

        Assert.assertNotNull(new SCIMGroupHandler(1).listSCIMRoles());
    }

}