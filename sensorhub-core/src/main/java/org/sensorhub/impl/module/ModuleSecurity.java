/***************************** BEGIN LICENSE BLOCK ***************************

The contents of this file are subject to the Mozilla Public License, v. 2.0.
If a copy of the MPL was not distributed with this file, You can obtain one
at http://mozilla.org/MPL/2.0/.

Software distributed under the License is distributed on an "AS IS" basis,
WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
for the specific language governing rights and limitations under the License.
 
Copyright (C) 2012-2016 Sensia Software LLC. All Rights Reserved.
 
******************************* END LICENSE BLOCK ***************************/

package org.sensorhub.impl.module;

import org.sensorhub.api.module.IModule;
import org.sensorhub.api.security.IAuthorizer;
import org.sensorhub.api.security.IPermission;
import org.sensorhub.api.security.IUser;
import org.sensorhub.impl.SensorHub;
import org.sensorhub.impl.security.ItemPermission;
import org.sensorhub.impl.security.ModulePermissions;
import org.sensorhub.impl.security.PermissionRequest;


public class ModuleSecurity
{    
    protected final ModulePermissions rootPerm;
    public final IPermission module_init;
    public final IPermission module_start;
    public final IPermission module_stop;
    public final IPermission module_update;
    ThreadLocal<IUser> currentUser = new ThreadLocal<IUser>();
    
    
    public ModuleSecurity(IModule<?> module)
    {
        rootPerm = new ModulePermissions(module.getLocalID(), module.getClass());
        
        // register basic module permissions        
        module_init = new ItemPermission(rootPerm, "init", "Unallowed to initialize module");
        module_start = new ItemPermission(rootPerm, "start", "Unallowed to start module");
        module_stop = new ItemPermission(rootPerm, "stop", "Unallowed to stop module");
        module_update = new ItemPermission(rootPerm, "update", "Unallowed to update module configuration");
        
        SensorHub.getInstance().getSecurityManager().registerModulePermissions(module.getLocalID(), rootPerm);
    }
    
    
    public void check(IPermission perm) throws SecurityException
    {
        // retrieve currently logged in user
        IUser user = currentUser.get();
        if (user == null)
            //throw new SecurityException(perm.getErrorMessage() + ": No user specified");
            return;
        
        // request authorization
        IAuthorizer auth = SensorHub.getInstance().getSecurityManager().getAuthorizer();
        if (!auth.hasPermission(user, new PermissionRequest(perm)))
            throw new SecurityException(perm.getErrorMessage() + ": User=" + user.getId());
    }
    
    
    public void setCurrentUser(String userID)
    {
        // lookup user info 
        IUser user = SensorHub.getInstance().getSecurityManager().getUser(userID);
        if (user == null)
            throw new SecurityException("Permission denied: Unknown user " + userID);
        
        currentUser.set(user);
    }
    
    
    public void clearCurrentUser()
    {
        currentUser.remove();
    }
}
