/***************************** BEGIN LICENSE BLOCK ***************************

 The contents of this file are subject to the Mozilla Public License Version
 1.1 (the "License"); you may not use this file except in compliance with
 the License. You may obtain a copy of the License at
 http://www.mozilla.org/MPL/MPL-1.1.html
 
 Software distributed under the License is distributed on an "AS IS" basis,
 WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 for the specific language governing rights and limitations under the License.
 
 The Original Code is "SensorHub".
 
 The Initial Developer of the Original Code is Sensia Software LLC.
 <http://www.sensiasoftware.com>. Portions created by the Initial
 Developer are Copyright (C) 2013 the Initial Developer. All Rights Reserved.
 
 Please contact Alexandre Robin <alex.robin@sensiasoftware.com> for more 
 information.
 
 Contributor(s): 
    Alexandre Robin <alex.robin@sensiasoftware.com>
 
******************************* END LICENSE BLOCK ***************************/

package org.sensorhub.api.module;

import java.io.Serializable;
import com.esotericsoftware.kryo.Kryo;


/**
 * <p>
 * Base class to hold modules' configuration options
 * </p>
 *
 * <p>Copyright (c) 2010</p>
 * @author Alexandre Robin
 * @since Nov 16, 2010
 */
public class ModuleConfig implements Serializable, Cloneable
{
    private static final long serialVersionUID = 2267529983474592096L;
    
    
    /**
     * Unique ID of the module. It must be unique within the SensorHub instance
     * and remain the same during the whole life-time of the module
     */
    public String id;
    
    
    /**
     * Name of module that this configuration is for
     */
    public String name;
    
    
    /**
     * Class implementing the module (to be instantiated)
     */
    public String moduleClass;
    
    
    /**
     * Used to enable/disable the module
     */
    public boolean enabled = false;
    
    
    @Override
    public ModuleConfig clone()
    {
        Kryo kryo = new Kryo();
        return kryo.copy(this);
    }
}