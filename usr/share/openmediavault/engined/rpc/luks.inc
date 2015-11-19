<?php
/**
 * This file is part of OpenMediaVault.
 *
 * @license   http://www.gnu.org/licenses/gpl.html GPL Version 3
 * @author    Volker Theile <volker.theile@openmediavault.org>
 * @author    OpenMediaVault Plugin Developers <plugins@omv-extras.org>
 * @copyright Copyright (c) 2009-2015 Volker Theile
 * @copyright Copyright (c) 2015 OpenMediaVault Plugin Developers
 *
 * OpenMediaVault is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * OpenMediaVault is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OpenMediaVault. If not, see <http://www.gnu.org/licenses/>.
 */
require_once("openmediavault/object.inc");
require_once("openmediavault/error.inc");
require_once("openmediavault/system.inc");
require_once("openmediavault/functions.inc");
require_once("openmediavault/luks.inc");
require_once("openmediavault/rpcservice.inc");
require_once("openmediavault/notify.inc");

class OMVRpcServiceLuksMgmt extends OMVRpcServiceAbstract {

    private $mountOnUnlock = TRUE;

    /**
     * Get the RPC service name.
     */
    public function getName() {
        return "LuksMgmt";
    }

    /**
     * Initialize the RPC service.
     */
    public function initialize() {
        if(isset($GLOBALS['OMV_LUKS_MOUNT_ON_UNLOCK']))
            $this->mountOnUnlock = boolvalEx($GLOBALS['OMV_LUKS_MOUNT_ON_UNLOCK']);

        $this->registerMethod("enumerateContainers");
        $this->registerMethod("getContainersList");
        $this->registerMethod("getContainerCandidates");
        $this->registerMethod("getContainerDetails");
        $this->registerMethod("createContainer");
        $this->registerMethod("deleteContainer");
        $this->registerMethod("modifyContainer");
        $this->registerMethod("openContainer");
        $this->registerMethod("closeContainer");
        $this->registerMethod("addContainerPassphrase");
        $this->registerMethod("changeContainerPassphrase");
        $this->registerMethod("removeContainerPassphrase");
        $this->registerMethod("testContainerKey");
        $this->registerMethod("killContainerKeySlot");
        $this->registerMethod("backupContainerHeader");
        $this->registerMethod("restoreContainerHeader");
    }

    /**
     * Enumerate all LUKS containers on the system.
     * @param params The method parameters.
     * @param context The context of the caller.
     * @return An array of objects. Each object represents a LUKS container
     *     with the following properties:
     *     device file, uuid, size, status
     * @throw E_EXEC_MISC
     */
    public function enumerateContainers($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, array(
            "role" => OMV_ROLE_ADMINISTRATOR
        ));
        // Enumerate all LUKS containers on the system.
        if (FALSE === ($devs = OMVLuksContainers::enumerate())) {
            throw new OMVException(OMVErrorMsg::E_EXEC_MISC,
                gettext("Failed to get list of encrypted devices"));
        }
        $result = array();
        foreach($devs as $devk => $devv) {
            // Get the container details.
            $luks = new OMVLuksContainer($devv);
            if(!$luks->exists())
                continue;
            $result[] = array(
                "devicefile"            => $luks->getDeviceFile(),
                "uuid"                  => $luks->getUuid(),
                "size"                  => $luks->getSize(),
                "unlocked"              => $luks->isOpen(),
                "decrypteddevicefile"   => $luks->getDecryptedDeviceFile(),
                "usedslots"             => $luks->getUsedKeySlots()
            );
        }
        return $result;
    }

    /**
     * Get a list of LUKS containers.
     * @param params An array containing the following fields:
     *     \em start The index where to start.
     *     \em limit The number of objects to process.
     *     \em sortfield The name of the column used to sort.
     *     \em sortdir The sort direction, ASC or DESC.
     * @param context The context of the caller.
     * @return An array containing the requested objects. The field \em total
     *     contains the total number of objects, \em data contains the object
     *     array. An exception will be thrown in case of an error.
     */
    function getContainersList($params, $context) {
        global $xmlConfig;
        // Validate the RPC caller context.
        $this->validateMethodContext($context, array(
            "role" => OMV_ROLE_ADMINISTRATOR
        ));
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, '{
            "type":"object",
            "properties":{
                "start":        {"type":"integer"},
                "limit":        {'.$GLOBALS['OMV_JSONSCHEMA_COUNTFIELD'].'},
                "sortfield":    {'.$GLOBALS['OMV_JSONSCHEMA_SORTFIELD'].'},
                "sortdir":      {'.$GLOBALS['OMV_JSONSCHEMA_SORTDIR'].'}
            }
        }');
        // Enumerate all LUKS containers on the system.
        $containers = $this->callMethod("enumerateContainers", NULL, $context);
        foreach($containers as $luksk => &$luksv) {
            $used = (!$luksv['unlocked']) ? NULL : FALSE;
            // If open, does the container contain a filesystem and is it known
            // or used (i.e. a configured mntent, aka referenced in /etc/fstab)?
            if(!is_null($used)) {
                if(FALSE !== ($meObject = OMVRpc::exec("FsTab", "getByFsName",
                    array("id" => $luksv['decrypteddevicefile']), $context))) {
                        $used = TRUE;
                }
            }
            // null if locked, otherwise true if used, false if not
            $luksv['_used'] = $used;
        }
        // Filter result.
        return $this->applyFilter($containers,
                                    $params['start'],
                                    $params['limit'],
                                    $params['sortfield'],
                                    $params['sortdir']
                                 );
    }

    /**
     * Get list of devices that can be used to create a LUKS container.
     * @param params The method parameters.
     * @param context The context of the caller.
     * @return An array containing objects with the following fields:
     *     devicefile, size and description.
     * @throw E_EXEC_MISC
     */
    public function getContainerCandidates($params, $context) {
        global $xmlConfig;
        // Validate the RPC caller context.
        $this->validateMethodContext($context, array(
            "role" => OMV_ROLE_ADMINISTRATOR
        ));
        // Get a list of all potential usable devices.
        if (FALSE === ($devs = OMVStorageDevices::enumerateUnused())) {
            throw new OMVException(OMVErrorMsg::E_EXEC_MISC,
                gettext("Failed to get list of devices"));
        }
        // Prepare the result list.
        $result = array();
        foreach ($devs as $devk => $devv) {
            // Get the object that implements the given storage device.
            $sd = OMVStorageDeviceFactory::get($devv);
            if (is_null($sd) || !$sd->exists())
                continue;
            // Skip read-only devices like CDROM.
            if (TRUE === $sd->isReadOnly())
                continue;
            // Check if device is referenced/used by a plugin.
            $xpath = sprintf("//services/devicefile[contains(.,'%s')]",
                                $sd->getDeviceFile());
            if (TRUE === $xmlConfig->exists($xpath))
                continue;
            // Does this device already contain a filesystem?
            if (FALSE !== OMVFilesystem::hasFileSystem($sd->getDeviceFile()))
                continue;
            // Is the device an already open LUKS container?
            // Don't allow LUKS-on-LUKS
            $luks = new OMVStorageDeviceLUKS($sd->getDeviceFile());
            if (TRUE === $luks->isLuks())
                continue;
            // The device is a potential candidate
            // to be used as a LUKS container.
            $result[] = array(
                "devicefile"    => $sd->getDeviceFile(),
                "size"          => $sd->getSize(),
                "description"   => $sd->getDescription()
            );
        }
        return $result;
    }

    /**
     * Get detail about a LUKS device.
     * @param params An array containing the following fields:
     *     \em devicefile The LUKS device file to get details from.
     * @param context The context of the caller.
     * @return The details of the given LUKS device as string.
     * @throw E_MISC_DEVICE_NOT_FOUND
     */
    public function getContainerDetails($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, array(
            "role" => OMV_ROLE_ADMINISTRATOR
        ));
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, '{
            "type":"object",
            "properties":{
                "devicefile":{'.$GLOBALS['OMV_JSONSCHEMA_DEVICEFILE'].'}
            }
        }');
        // Get software RAID device details.
        $luks = new OMVLuksContainer($params['devicefile']);
        if(FALSE === $luks->exists()) {
            throw new OMVException(OMVErrorMsg::E_MISC_DEVICE_NOT_FOUND,
                sprintf(gettext("LUKS container on '%s' not found"),
                        $params['devicefile']));
        }
        return $luks->getDetail();
    }

    /**
     * Open (unlock) a LUKS container.
     * @param params An array containing the following fields:
     *     \em UUID The UUID of the LUKS container device to open.
     *     \em devicefile The block special device of the LUKS container to open.
     *      And containing either passphrase or filename/path fields:
     *     \em passphrase The passphrase to unlock the device.
     *     \em filename The filename of the key file to unlock the device.
     *     \em filepath Path to the uploaded key file.
     * @param context The context of the caller.
     * @return None
     * @throw E_MISC_FAILURE
     */
    public function openContainer($params, $context) {
        global $xmlConfig;
        // Validate the RPC caller context.
        $this->validateMethodContext($context, array(
                "role" => OMV_ROLE_ADMINISTRATOR
        ));
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, '{
            "type":"object",
            "properties":{
                "uuid":         {'.$GLOBALS['OMV_JSONSCHEMA_UUID'].'},
                "devicefile":	{'.$GLOBALS['OMV_JSONSCHEMA_DEVICEFILE'].'},
                "passphrase":	{"type":"string", "optional":"true"},
                "filename":	    {"type":"string", "optional":"true"},
                "filepath":	    {"type":"string", "optional":"true"}
            }
        }');
        // Validate the container
        $luks = new OMVLuksContainer($params['devicefile']);
        if (is_null($luks) || !$luks->exists()) {
            throw new OMVException(OMVErrorMsg::E_MISC_FAILURE,
                sprintf(gettext("LUKS container on '%s' not found"),
                        $params['devicefile']));
        }
        // Check that the container is not already open, then use
        // the supplied passphrase or key file to unlock it if not.
        if (FALSE === $luks->isOpen()) {
            if(isset($params['filename'], $params['filepath'])) {
                // Test key file
                $success = $luks->openWithKeyFile($params);
                // As an added precaution, shred the key file
                // before it is removed when cleaning up.
                $cmd = sprintf("export LANG=C; shred %s ",
                                escapeshellarg($params['filepath']));
                @OMVUtil::exec($cmd, $output, $result);
                if ($result !== 0)
                    $this->debug($output);
            } else {
                // Test passphrase
                $success = $luks->openWithPassphrase($params);
            }
            if ($success === FALSE) {
                throw new OMVException(OMVErrorMsg::E_MISC_FAILURE,
                    sprintf(gettext("Unable to unlock encrypted device: %s"),
                            $luks->getLastError()));
            }
        }
        // If the container contains a (referenced) filesystem, then mount it
        // (unless this automounting is disabled by the global configuration
        // option, OMV_LUKS_MOUNT_ON_UNLOCK - see initialize() above)
        if(TRUE === $this->mountOnUnlock) {
            $sdluks = new OMVStorageDeviceLUKS($luks->getDecryptedDeviceFile());
            $df = $sdluks->getDeviceFile();
            if(FALSE !== OMVRpc::exec("FileSystemMgmt", "hasFilesystem",
                            array("devicefile" => $df), $context)) {
                if(FALSE !== ($meObject = OMVRpc::exec("FsTab", "getByFsName",
                                array("id" => $df), $context))) {
                    switch (strtolower($meObject['type'])) {
                    case "btrfs":
                        /**
                         * Check if the unlocked device is part of a multi-
                         * device BTRFS filesystem, and don't attempt to mount
                         * it if it's not ready (not all devices are available,
                         * e.g. if more containers must be unlocked first, wait
                         * until they are all open).
                         * Note that this only works for the first time devices
                         * are opened - even if LUKS devices that are part of a
                         * multi-device BTRFS filesystem are later closed, some
                         * information is cached and so btrfs subsequently
                         * always reports the filesystem as ready.
                         */
                        $cmd = sprintf("export LANG=C; btrfs device ready %s",
                                        $luks->getDecryptedDeviceFile());
                        @OMVUtil::exec($cmd, $output, $result);
                        if($result !== 0) {
                            $this->setLastError($output);
                            continue;
                        }
                    case "ext2":
                    case "ext3":
                    case "ext4":
                    case "jfs":
                    case "xfs":
                    case "hfsplus":
                    case "reiserfs":
                    case "iso9660":
                    case "udf":
                    case "vfat":
                    case "ntfs":
                    default:
                        OMVRpc::exec("FileSystemMgmt", "mount",
                            array(
                                    "id" => $meObject['fsname'],
                                    "fstab" => FALSE
                                 ),
                            $context);
                    }
                }
            }
        }
    }

    /**
     * Close (lock) a LUKS container.
     * @param params An array containing the following fields:
     *     \em devicefile The block special device of the LUKS container to close.
     * @param context The context of the caller.
     * @return None.
     * @throw E_MISC_FAILURE
     */
    public function closeContainer($params, $context) {
        global $xmlConfig;
        // Validate the RPC caller context.
        $this->validateMethodContext($context, array(
            "role" => OMV_ROLE_ADMINISTRATOR
        ));
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, '{
            "type":"object",
            "properties":{
                "devicefile":{'.$GLOBALS['OMV_JSONSCHEMA_DEVICEFILE'].'}
            }
        }');
        // Validate the container
        $luks = new OMVLuksContainer($params['devicefile']);
        if (is_null($luks) || !$luks->exists()) {
            throw new OMVException(OMVErrorMsg::E_MISC_FAILURE,
                sprintf(gettext("LUKS container on '%s' not found"),
                        $params['devicefile']));
        }
        // Check if the container is open, and proceed to close it if so
        if (TRUE === $luks->isOpen()) {
            if (FALSE === $luks->close()) {
                throw new OMVException(OMVErrorMsg::E_MISC_FAILURE,
                    sprintf(gettext("Unable to lock encrypted device: %s"),
                            $luks->getLastError()));
            }
        }
    }

    /**
     * Create a LUKS container.
     * @param params An array containing the following fields:
     *     \em devicefile The device file where to create the LUKS container.
     *     \em passphrase The passphrase to unlock the device.
     * @param context The context of the caller.
     * @return None.
     * @throw E_MISC_DEVICE_NOT_FOUND
     * @throw E_EXEC_FAILED
     */
    public function createContainer($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, array(
            "role" => OMV_ROLE_ADMINISTRATOR
        ));
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, '{
            "type":"object",
            "properties":{
                "devicefile":{'.$GLOBALS['OMV_JSONSCHEMA_DEVICEFILE'].'},
                "passphrase":{"type": "string"}
            }
        }');
        // Get the storage device object.
        $sd = OMVStorageDeviceFactory::get($params['devicefile']);
        if (is_null($sd) || !$sd->exists()) {
            throw new OMVException(OMVErrorMsg::E_MISC_DEVICE_NOT_FOUND,
                $params['devicefile']);
        }
        // Get the storage device backend of the given device.
        $sdb = OMVStorageDevices::getBackend($sd->getDeviceFile());
        if (is_null($sdb)) {
            throw new OMVException(OMVErrorMsg::E_MISC_FAILURE, sprintf(
                "No storage device backend exists for device %s",
                $sd->getDeviceFile()));
        }
        switch ($sdb->getType()) {
        case OMV_STORAGE_DEVICE_TYPE_SOFTWARERAID:
        case OMV_STORAGE_DEVICE_TYPE_DEVICEMAPPER:
            // Wipe existing filesystems.
            $cmd = sprintf("export LANG=C; wipefs -a %s 2>&1",
                            $sd->getDeviceFile());
            @OMVUtil::exec($cmd, $output, $result);
            if ($result !== 0) {
                throw new OMVException(OMVErrorMsg::E_EXEC_FAILED,
                    $cmd, implode("\n", $output));
            }
            break;
        default:
            // Wipe existing filesystems.
            $cmd = sprintf("export LANG=C; sgdisk --zap-all %s 2>&1",
                            escapeshellarg($sd->getDeviceFile()));
            @OMVUtil::exec($cmd, $output, $result);
            if ($result !== 0) {
                throw new OMVException(OMVErrorMsg::E_EXEC_FAILED,
                    $cmd, implode("\n", $output));
            }
            break;
        }
        // Reread partition table.
        $cmd = sprintf("export LANG=C; partprobe %s",
                        escapeshellarg($sd->getDeviceFile()));
        @OMVUtil::exec($cmd, $output, $result);
        if ($result !== 0) {
            throw new OMVException(OMVErrorMsg::E_EXEC_FAILED,
                $cmd, implode("\n", $output));
        }
        // Create the container.
        $luks = new OMVLuksContainer($sd->getDeviceFile());
        if (!$luks->create($params)) {
            throw new OMVException(OMVErrorMsg::E_EXEC_MISC, sprintf(
                gettext("Failed to create encrypted device: %s"),
                $luks->getLastError()));
        }
        // Notify configuration changes.
        $dispatcher = &OMVNotifyDispatcher::getInstance();
        $dispatcher->notify(OMV_NOTIFY_CREATE,
            "org.openmediavault.system.storage.luks.container", array(
                "devicefile" => $params['devicefile']
        ));
    }

    /**
     * Delete a LUKS container.
     * @param params An array containing the following fields:
     *     \em devicefile The devicefile of the LUKS device.
     * @param context The context of the caller.
     * @return None.
     * @throw E_MISC_FAILURE
     * @throw E_EXEC_MISC
     */
    public function deleteContainer($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, array(
            "role" => OMV_ROLE_ADMINISTRATOR
        ));
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, '{
            "type":"object",
            "properties":{
                "devicefile":{'.$GLOBALS['OMV_JSONSCHEMA_DEVICEFILE'].'}
            }
        }');
        // Check if the container exists.
        $luks = new OMVLuksContainer($params['devicefile']);
        if (!$luks->exists()) {
            throw new OMVException(OMVErrorMsg::E_MISC_FAILURE,
                sprintf(gettext("No encryption found on '%s'"),
                $params['devicefile']));
        }
        // Remove the container.
        if (!$luks->remove()) {
            throw new OMVException(OMVErrorMsg::E_EXEC_MISC, sprintf(
                gettext("Failed to remove the encrypted device: %s"),
                $luks->getLastError()));
        }
        // Notify configuration changes.
        $dispatcher = &OMVNotifyDispatcher::getInstance();
        $dispatcher->notify(OMV_NOTIFY_DELETE,
            "org.openmediavault.system.storage.luks.container", array(
                "devicefile" => $params['devicefile']
        ));
    }

    /**
     * Modify a LUKS container.
     * @param params An array containing the following fields:
     *     \em devicefile The device file of the container to modify.
     *     \em openatboot A boolean value representing whether to unlock
     *         the encrypted device at boot or not.
     * @param context The context of the caller.
     * @return None.
     * @throw E_MISC_FAILURE
     * @throw E_EXEC_FAILED
     */
    public function modifyContainer($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, array(
            "role" => OMV_ROLE_ADMINISTRATOR
        ));
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, '{
            "type":"object",
            "properties":{
                "devicefile":{'.$GLOBALS['OMV_JSONSCHEMA_DEVICEFILE'].'},
                "openatboot":{"type":"boolean"}
            }
        }');
        // Check if container exists.
        $luks = new OMVLuksContainer($params['devicefile']);
        if (FALSE === $luks->exists()) {
            throw new OMVException(OMVErrorMsg::E_MISC_FAILURE,
                sprintf(gettext("No encryption found on '%s'"),
                $params['devicefile']));
        }
        // Set the unlock at boot status
        // TODO: change crypttab method
        // Notify configuration changes.
        $dispatcher = &OMVNotifyDispatcher::getInstance();
        $dispatcher->notify(OMV_NOTIFY_MODIFY,
            "org.openmediavault.system.storage.luks.container", array(
                "devicefile" => $params['devicefile'],
                "openatboot" => array_boolval($params, "openatboot")
        ));
    }

    /**
     * Add a passphrase for a container.
     * @param params An array containing the following fields:
     *     \em devicefile The device file of the container to modify.
     *     \em oldpassphrase A current passphrase that will unlock the device.
     *     \em newpassphrase The new passphrase to add.
     * @param context The context of the caller.
     * @return None.
     * @throw E_MISC_FAILURE
     * @throw E_EXEC_FAILED
     */
    public function addContainerPassphrase($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, array(
            "role" => OMV_ROLE_ADMINISTRATOR
        ));
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, '{
            "type":"object",
            "properties":{
                "devicefile":{'.$GLOBALS['OMV_JSONSCHEMA_DEVICEFILE'].'},
                "oldpassphrase":{"type":"string"},
                "newpassphrase":{"type":"string"}
            }
        }');
        // Check if container exists.
        $luks = new OMVLuksContainer($params['devicefile']);
        if (FALSE === $luks->exists()) {
            throw new OMVException(OMVErrorMsg::E_MISC_FAILURE,
              sprintf(gettext("No encryption found on '%s'"),
                        $params['devicefile']));
        }
        // Change passphrase.
        if (!$luks->addKey($params)) {
            throw new OMVException(OMVErrorMsg::E_EXEC_MISC, sprintf(
                gettext("Failed to add the passphrase to the encrypted device: %s"),
                $luks->getLastError()));
        }
    }

    /**
     * Change a passphrase for a container.
     * @param params An array containing the following fields:
     *     \em devicefile The device file of the container to modify.
     *     \em oldpassphrase The current passphrase to unlock the device.
     *     \em newpassphrase The new passphrase to replace the old one with.
     * @param context The context of the caller.
     * @return None.
     * @throw E_MISC_FAILURE
     * @throw E_EXEC_FAILED
     */
    public function changeContainerPassphrase($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, array(
            "role" => OMV_ROLE_ADMINISTRATOR
        ));
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, '{
            "type":"object",
            "properties":{
                "devicefile":{'.$GLOBALS['OMV_JSONSCHEMA_DEVICEFILE'].'},
                "oldpassphrase":{"type":"string"},
                "newpassphrase":{"type":"string"}
            }
        }');
        // Check if container exists.
        $luks = new OMVLuksContainer($params['devicefile']);
        if (FALSE === $luks->exists()) {
            throw new OMVException(OMVErrorMsg::E_MISC_FAILURE,
                sprintf(gettext("No encryption found on '%s'"),
                        $params['devicefile']));
        }
        // Change passphrase.
        if (!$luks->changeKey($params)) {
            throw new OMVException(OMVErrorMsg::E_EXEC_MISC, sprintf(
                gettext("Failed to change the passphrase for the encrypted device: %s"),
                $luks->getLastError()));
        }
    }

    /**
     * Remove a passphrase from a container.
     * @param params An array containing the following fields:
     *     \em devicefile The device file of the container to modify.
     *     \em passphrase The passphrase to remove from the device.
     * @param context The context of the caller.
     * @return None.
     * @throw E_MISC_FAILURE
     * @throw E_EXEC_FAILED
     */
    public function removeContainerPassphrase($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, array(
            "role" => OMV_ROLE_ADMINISTRATOR
        ));
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, '{
            "type":"object",
            "properties":{
                "devicefile":{'.$GLOBALS['OMV_JSONSCHEMA_DEVICEFILE'].'},
                "passphrase":{"type":"string"}
            }
        }');
        // Check if container exists.
        $luks = new OMVLuksContainer($params['devicefile']);
        if (FALSE === $luks->exists()) {
            throw new OMVException(OMVErrorMsg::E_MISC_FAILURE,
              sprintf(gettext("No encryption found on '%s'"),
                        $params['devicefile']));
        }
        // Change passphrase.
        if (!$luks->removeKey($params)) {
            throw new OMVException(OMVErrorMsg::E_EXEC_MISC, sprintf(
                gettext("Failed to remove the passphrase from the encrypted device: %s"),
                $luks->getLastError()));
        }
    }

    /**
     * Test whether a key unlocks a container.
     * @param params An array containing the following fields:
     *     \em UUID The UUID of the LUKS container device to open.
     *     \em devicefile The block special device of the LUKS container to open.
     *      And containing either passphrase or filename/path fields:
     *     \em passphrase The passphrase to unlock the device.
     *     \em filename The filename of the key file to unlock the device.
     *     \em filepath Path to the uploaded key file.
     * @param context The context of the caller.
     * @return An integer from 0-7 representing which keyslot the
     *          passphrase successfully unlocked, otherwise none.
     * @throw E_MISC_FAILURE
     */
    public function testContainerKey($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, array(
            "role" => OMV_ROLE_ADMINISTRATOR
        ));
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, '{
            "type":"object",
            "properties":{
                "uuid":         {'.$GLOBALS['OMV_JSONSCHEMA_UUID'].'},
                "devicefile":	{'.$GLOBALS['OMV_JSONSCHEMA_DEVICEFILE'].'},
                "passphrase":	{"type":"string", "optional":"true"},
                "filename":	    {"type":"string", "optional":"true"},
                "filepath":	    {"type":"string", "optional":"true"}
            }
        }');
        // Validate the container
        $luks = new OMVLuksContainer($params['devicefile']);
        if (is_null($luks) || !$luks->exists()) {
            throw new OMVException(OMVErrorMsg::E_MISC_FAILURE,
                sprintf(gettext("LUKS container on '%s' not found"),
                        $params['devicefile']));
        }
        // Test the key
        if(isset($params['filename'], $params['filepath'])) {
            // Test key file
            $slot = $luks->testKeyFile($params);
            // As an added precaution, shred the key file
            // before it is removed when cleaning up.
            $cmd = sprintf("export LANG=C; shred %s ",
                            escapeshellarg($params['filepath']));
            @OMVUtil::exec($cmd, $output, $result);
            if ($result !== 0)
                $this->debug($output);
        } else {
            $slot = $luks->testPassphrase($params);
        }
        if ($slot === FALSE) {
            throw new OMVException(OMVErrorMsg::E_MISC_FAILURE,
              sprintf(gettext("The key did not unlock any key slot on the device")));
        } else {
            return $slot;
        }
    }

    /**
     * Kill a keyslot on the container.
     * @param params An array containing the following fields:
     *     \em devicefile The device file of the container to modify.
     *     \em passphrase A current passphrase that will unlock the device.
     *     \em keyslot A number from 0-7 representing which keyslot to kill.
     * @param context The context of the caller.
     * @return None.
     * @throw E_MISC_FAILURE
     * @throw E_EXEC_FAILED
     */
    public function killContainerKeySlot($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, array(
            "role" => OMV_ROLE_ADMINISTRATOR
        ));
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, '{
            "type":"object",
            "properties":{
                "devicefile":{'.$GLOBALS['OMV_JSONSCHEMA_DEVICEFILE'].'},
                "passphrase":{"type":"string"},
                "keyslot":{ "type": "integer", "minimum":0, "maximum":7 }
            }
        }');
        // Check if container exists.
        $luks = new OMVLuksContainer($params['devicefile']);
        if (FALSE === $luks->exists()) {
            throw new OMVException(OMVErrorMsg::E_MISC_FAILURE,
              sprintf("No encryption found on '%s'",
                        $params['devicefile']));
        }
        // Kill the keyslot.
        if (!$luks->killKeySlot($params)) {
            throw new OMVException(OMVErrorMsg::E_EXEC_MISC, sprintf(
                gettext("Failed to kill the key slot on the encrypted device: %s"),
                $luks->getLastError()));
        }
    }

    /**
     * Backup the container header.
     * @param params An array containing the following fields:
     *     \em devicefile The device file of the container to modify.
     * @param context The context of the caller.
     * @return An array with the following keys:
     *     \em filename Filename of the header backup being downloaded.
     *     \em filepath Location of the temporary file.
     *     \em unlink Whether to delete the temporary file after downloading.
     * @throw E_MISC_FAILURE
     * @throw E_EXEC_FAILED
     */
    public function backupContainerHeader($params, $context) {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, array(
            "role" => OMV_ROLE_ADMINISTRATOR
        ));
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, '{
            "type":"object",
            "properties":{
                "devicefile":{'.$GLOBALS['OMV_JSONSCHEMA_DEVICEFILE'].'}
            }
        }');
        // Check if container exists.
        $luks = new OMVLuksContainer($params['devicefile']);
        if (FALSE === $luks->exists()) {
            throw new OMVException(OMVErrorMsg::E_MISC_FAILURE,
                sprintf(gettext("No encryption found on '%s'"),
                $params['devicefile']));
        }
        // Extract the header to a temporary location and modify the
        // file mode/owner to allow the WebGUI PHP backend to unlink it.
        $tmpFilePath = sys_get_temp_dir()."/".uniqid("luksHeader");
        $params['backupfile'] = $tmpFilePath;
        if (!$luks->backupHeader($params)) {
            throw new OMVException(OMVErrorMsg::E_EXEC_MISC, sprintf(
                gettext("Failed to extract the LUKS header from ".
                        "the encrypted device: %s"),
                $luks->getLastError()));
        }
        // Adjust header backup temporary file permissions and ownership so
        // that the WebGUI can delete it after downloading.
        chmod($tmpFilePath, 0600);
        chgrp($tmpFilePath, $GLOBALS['OMV_WEBGUI_FILE_OWNERGROUP_NAME']);
        chown($tmpFilePath, $GLOBALS['OMV_WEBGUI_FILE_OWNERGROUP_NAME']);
        // Return values required by generic download RPC implementation.
        return array(
            "filename"       => "LUKS_header_".$luks->getUuid().".bak",
            "filepath"       => $tmpFilePath,
            "contenttype"    => "application/octet-stream",
            "unlink"         => TRUE
        );
    }

    /**
     * Restore the container header.
     * @param params An array containing the following fields:
     *     \em devicefile The device file of the container to modify.
     *     \em uuid The existing UUID of the encrypted device.
     *     \em force Boolean, whether to proceed even if the UUID from
     *          the backup doesn't match that on the device.
     *     \em filename The original name of the file.
     *     \em filepath The path to the uploaded file.
     * @param context The context of the caller.
     * @return None
     * @throw E_MISC_DEVICE_NOT_FOUND
     * @throw E_MISC_FAILURE
     * @throw E_EXEC_FAILED
     */
    public function restoreContainerHeader($params, $context) {
        print_r($params);
        // Validate the RPC caller context.
        $this->validateMethodContext($context, array(
            "role" => OMV_ROLE_ADMINISTRATOR
        ));
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, '{
            "type":"object",
            "properties":{
                "devicefile":   {'.$GLOBALS['OMV_JSONSCHEMA_DEVICEFILE'].'},
                "uuid":         {'.$GLOBALS['OMV_JSONSCHEMA_UUID'].'},
                "force":        {"type":"boolean"},
                "filename":     {"type":"string"},
                "filepath":     {"type":"string"}
            }
        }');
        // Get the storage device object.
        $sd = OMVStorageDeviceFactory::get($params['devicefile']);
        if (is_null($sd) || !$sd->exists()) {
            throw new OMVException(OMVErrorMsg::E_MISC_DEVICE_NOT_FOUND,
                $params['devicefile']);
        }
        // Get the storage device backend of the given device.
        $sdb = OMVStorageDevices::getBackend($sd->getDeviceFile());
        if (is_null($sdb)) {
            throw new OMVException(OMVErrorMsg::E_MISC_FAILURE, sprintf(
                gettext("No storage device backend exists for device %s"),
                $sd->getDeviceFile()));
        }
        // Validate the new header
        $cmd = sprintf("export LANG=C; cryptsetup isLuks %s 2>&1",
                        $params['filepath']);
        @OMVUtil::exec($cmd, $output, $result);
        if ($result !== 0) {
            throw new OMVException(OMVErrorMsg::E_MISC_FAILURE,
                sprintf(gettext("%s is not a valid LUKS header backup file"),
                        $params['filename']));
        }
        // Check the UUIDs match, unless force is set
        if($params['force'] === FALSE) {
            unset($cmd, $output, $result);
            $cmd = sprintf("export LANG=C; cryptsetup luksUUID %s 2>&1",
                            $params['filepath']);
            @OMVUtil::exec($cmd, $output, $result);
            $header_uuid = $output[0];
            if($header_uuid !== $params['uuid']) {
                throw new OMVException(OMVErrorMsg::E_MISC_FAILURE,
                    sprintf(gettext("The UUID of the LUKS header backup file ".
                            "doesn't match the device. If you are sure you ".
                            "want to write this header to the device, try ".
                            "again with the 'force' option enabled.".PHP_EOL.
                            "Target device UUID:".PHP_EOL." %s".PHP_EOL.
                            "Header backup UUID:".PHP_EOL." %s"),
                            $params['uuid'],
                            $header_uuid
                           ));
            }
        }
        // Write the header to the device
        $luks = new OMVLuksContainer($params['devicefile']);
        if (!$luks->restoreHeader($params)) {
            throw new OMVException(OMVErrorMsg::E_EXEC_MISC, sprintf(
                gettext("Failed to restore the LUKS header to ".
                        "device %s: %s"),
                $params['devicefile'],
                $luks->getLastError()));
        }
    }
}

// Register the RPC service.
$rpcServiceMgr = &OMVRpcServiceMgr::getInstance();
$rpcServiceMgr->registerService(new OMVRpcServiceLuksMgmt());
