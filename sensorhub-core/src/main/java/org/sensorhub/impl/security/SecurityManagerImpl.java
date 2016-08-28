/***************************** BEGIN LICENSE BLOCK ***************************

The contents of this file are subject to the Mozilla Public License, v. 2.0.
If a copy of the MPL was not distributed with this file, You can obtain one
at http://mozilla.org/MPL/2.0/.

Software distributed under the License is distributed on an "AS IS" basis,
WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
for the specific language governing rights and limitations under the License.
 
Copyright (C) 2012-2016 Sensia Software LLC. All Rights Reserved.
 
******************************* END LICENSE BLOCK ***************************/

package org.sensorhub.impl.security;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.sensorhub.api.security.IAuthorizer;
import org.sensorhub.api.security.IPermission;
import org.sensorhub.api.security.IPermissionPath;
import org.sensorhub.api.security.ISecurityManager;
import org.sensorhub.api.security.IUser;
import org.sensorhub.api.security.IUserRole;


public class SecurityManagerImpl implements ISecurityManager
{
    Map<String, ModulePermissions> modulePermissions = new HashMap<String, ModulePermissions>();
    Map<String, IUser> users = new HashMap<String, IUser>();
        
    
    public SecurityManagerImpl()
    {
        final IUserRole adminRole = new IUserRole() {
            
            public String getName()
            {
                return "admin";
            }

            public Collection<IPermissionPath> getAllowList()
            {
                ArrayList<IPermissionPath> allowList = new ArrayList<IPermissionPath>();
                allowList.add(new PermissionSetting(new WildcardPermission()));
                return allowList;
            }

            public Collection<IPermissionPath> getDenyList()
            {
                return Collections.EMPTY_LIST;
            }            
        };
        
        final IPermission sosRoot = new ModulePermissions("5cb05c9c-9e08-4fa1-8731-ff41e246bdc1");
        final IPermission sosRead = new ItemPermission(sosRoot, "read");
        final IUserRole userRole = new IUserRole() {
            
            public String getName()
            {
                return "user";
            }

            public Collection<IPermissionPath> getAllowList()
            {
                ArrayList<IPermissionPath> allowList = new ArrayList<IPermissionPath>();
                allowList.add(new PermissionSetting(sosRead));
                //allowList.add(new PermissionSetting(new ItemPermission(sosRead, "caps")));
                //allowList.add(new PermissionSetting(new ItemPermission(sosRead, "obs")));
                return allowList;
            }

            public Collection<IPermissionPath> getDenyList()
            {
                ArrayList<IPermissionPath> denyList = new ArrayList<IPermissionPath>();
                denyList.add(new PermissionSetting(new ItemPermission(sosRead, "caps")));
                denyList.add(new PermissionSetting(new ItemPermission(sosRead, "sensor")));
                return denyList;
            }            
        };
        
        users.put("admin", new IUser() {
            
            public String getId()
            {
                return "admin";
            }

            public String getName()
            {
                return "Administrator";
            }

            public Collection<IUserRole> getRoles()
            {
                return Arrays.asList(adminRole);
            }
        });

        users.put("alex", new IUser() {
            
            public String getId()
            {
                return "alex";
            }

            public String getName()
            {
                return "Alex Robin";
            }

            public Collection<IUserRole> getRoles()
            {
                //return Arrays.asList(adminRole);
                return Arrays.asList(userRole);
            }
        });
    }
    
    
    @Override
    public IUser getUser(String userID)
    {
        return users.get(userID);
    }
    
    
    @Override
    public IAuthorizer getAuthorizer()
    {
        return new IAuthorizer() {

            @Override
            public boolean hasPermission(IUser user, IPermissionPath requestedPerm)
            {
                // check all roles
                for (IUserRole role: user.getRoles())
                {
                    boolean match = false;
                    
                    // check allowed permissions
                    for (IPermissionPath perm: role.getAllowList())
                    {
                        if (perm.implies(requestedPerm))
                        {
                            match = true;
                            break;
                        }
                    }
                    
                    // check denied permissions
                    for (IPermissionPath perm: role.getDenyList())
                    {
                        if (perm.implies(requestedPerm))
                        {
                            match = false;
                            break;
                        }
                    }
                                
                    // end here if this role allows access
                    if (match)
                        return true;
                }
                
                return false;
            }

            @Override
            public boolean hasPermission(IUser user, IPermissionPath requestedPerm, Map<IPermission, Object>... params)
            {
                // TODO Auto-generated method stub
                return false;
            }            
        };
    }


    @Override
    public void registerModulePermissions(String moduleID, ModulePermissions perm)
    {
        modulePermissions.put(moduleID, perm);
    }


    @Override
    public ModulePermissions getModulePermissions(String moduleID)
    {
        return modulePermissions.get(moduleID);
    }

}
