<?php
/**
 * @license   http://www.gnu.org/licenses/gpl.html GPL Version 3
 * @author    Volker Theile <volker.theile@openmediavault.org>
 * @author    OpenMediaVault Plugin Developers <plugins@omv-extras.org>
 * @copyright Copyright (c) 2009-2015 Volker Theile
 * @copyright Copyright (c) 2015-2016 OpenMediaVault Plugin Developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
namespace OMV\System\Storage\Luks;

use OMV\System;
use OMV\System\Filesystem\Backend\Manager;
use OMV\System\Process;

/**
 * Class for handling a LUKS-encrypted device (aka a LUKS container).
 */
class Container extends \OMV\System\Storage\StorageDevice {

    /**
     * Notes for cryptsetup:
     * Cryptsetup returns 0 on success and a non-zero value on error.
     * Error codes are:
     *  1 wrong parameters
     *  2 no permission (bad passphrase)
     *  3 out of memory
     *  4 wrong device specified
     *  5 device already exists or device is busy
     */
    protected $uuid         = "";
    protected $isOpen       = FALSE;
    protected $headerInfo   = "";
    protected $usedKeySlots = 0;
    protected $freeKeySlots = 8;

    protected $deviceMapperDeviceFile   = "";
    protected $deviceMapperName         = "";

    private $dataCached = FALSE;

    /**
     * Get the name of the device mapper device.
     * @return The name of the device mapper device.
     */
    public function getDeviceMapperName() {
        // Make sure the canonical device file is used to extract the name
        // of the device.
        $path = sprintf("/sys/class/block/%s/dm/name",
                        $this->getDeviceMapperCanonicalName());
        if(!file_exists($path))
            return FALSE;
        return trim(file_get_contents($path));
    }

    /**
     * Get the UUID of the device mapper device.
     * @return The UUID of the device mapper device, otherwise FALSE.
     */
    public function getDeviceMapperUuid() {
        // Make sure the canonical device file is used to extract the name
        // of the device.
        $path = sprintf("/sys/class/block/%s/dm/uuid",
                        $this->getDeviceMapperCanonicalName());
        if(!file_exists($path))
            return FALSE;
        return trim(file_get_contents($path));
    }

    /**
     * Get the holder device file of the container if it's open
     * @return A device file string (/dev/dm-0), otherwise FALSE.
     */
    public function getDeviceMapperDeviceFile() {
        if(FALSE === ($holders = $this->getHolders()))
            return FALSE;
        if(count($holders)!=1)
            return FALSE;
        return $holders[0]; // Should only be one holder, just return the first
    }

    /**
     * Get the holder device name of the container if it's open
     * @return A device name (dm-0), otherwise FALSE.
     */
    public function getDeviceMapperCanonicalName() {
        // Get the device file and extract the name, e.g. /dev/sda => sda.
        if(FALSE === ($dev = $this->getDeviceMapperDeviceFile())) {
            return FALSE;
        }
        $deviceName = str_replace("/dev/", "", $dev);
        return $deviceName;
    }

    /**
     * Get detailed information for the container.
     * @private
     * @return TRUE if successful, otherwise FALSE.
     */
    private function getData() {
        if($this->dataCached !== FALSE)
            return TRUE;

        // Reset cached data
        $this->uuid                     = "";
        $this->isOpen                   = FALSE;
        $this->headerInfo               = "";
        $this->usedKeySlots             = 0;
        $this->freeKeySlots             = 8;
        $this->deviceMapperDeviceFile   = "";
        $this->deviceMapperName         = "";

        // Look up the UUID for the LUKS container
        $cmd = sprintf("export LANG=C; cryptsetup luksUUID %s",
                        $this->getDeviceFile());
        $process = new Process($cmd);
        $process->execute($output,$result);
        $uuid = trim($output[0]);
        $this->uuid = $uuid;
        unset($cmd, $output, $result);

        // Get size of device
        $this->size = $this->getSize();

        // Check if the device is open and get the device mapper name if so
        if (FALSE !== ($dev = $this->getDeviceMapperDeviceFile())) {
            // Any devices of the form /dev/dm-n are for internal use only and
            // should never be used. Because of that the device file returned
            // should look like /dev/mapper/<xyz>. See for more information:
            // https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/html-single/DM_Multipath
            if(1 == preg_match("/^\/dev\/dm-\d+$/", $dev)) {
                if(FALSE !== ($name = $this->getDeviceMapperName())) {
                    $this->deviceMapperDeviceFile = sprintf("/dev/mapper/%s",
                                                            $name);
                    $this->deviceMapperName = $name;
                } else {
                    $this->deviceMapperDeviceFile = $dev;
                }
            }
            $this->isOpen = TRUE;
        }

        // Collect the detailed output from luksDump
        $cmd = sprintf("export LANG=C; cryptsetup luksDump %s",
                        $this->getDeviceFile());
        $process = new Process($cmd);
        $process->execute($output,$result);
        $this->headerInfo = $output;
        $this->usedKeySlots = count(preg_grep("/^Key Slot \d: ENABLED$/",
                                                $this->headerInfo));
        $this->freeKeySlots = count(preg_grep("/^Key Slot \d: DISABLED$/",
                                                $this->headerInfo));
        unset($cmd, $output, $result);

        // Set flag to mark information has been successfully read.
        $this->dataCached = TRUE;

        return TRUE;
    }

    /**
     * Refresh the cached information.
     * @return TRUE if successful, otherwise FALSE.
     */
    public function refresh() {
        $this->dataCached = FALSE;
        if($this->getData() === FALSE)
            return FALSE;
        return TRUE;
    }

    /**
     * Checks if the container exists - synonym for isLuks().
     * @return TRUE if the container exists, otherwise FALSE.
     */
    public function exists() {
        return $this->isLuks();
    }

    /**
     * Checks if the device exists and is a LUKS container
     * @return TRUE if the device is a LUKS container, otherwise FALSE.
     */
    public function isLuks() {
        if (FALSE === parent::exists())
            return FALSE;
        return self::isLuksContainer($this->getDeviceFile());
    }

    /**
     * Helper function for determining if a device is a LUKS container.
     * @return TRUE if the device is a LUKS container, otherwise FALSE.
     */
    public static function isLuksContainer($deviceFile) {
        // TODO: would it be better (quicker) to check the UUID
        // in, e.g., /sys/class/block/dm-0/dm/uuid (it begins
        // with 'CRYPTO' for LUKS/dm-crypt devices)?
        $cmd = sprintf("export LANG=C; cryptsetup isLuks %s",
                        escapeshellarg($deviceFile));
        $process = new Process($cmd);
        $process->setQuiet();
        $process->execute($output,$result);
        if (0 !== $result)
            return FALSE;
        return TRUE;
    }

    /**
     * Get the holder devices of the LUKS container (i.e. the
     * decrypted device, if open).
     * @return An array of device files, otherwise FALSE.
     */
    public function getHolders() {
        // Make sure the canonical device file is used to extract the name
        // of the device.
        $path = sprintf("/sys/class/block/%s/holders", $this->getDeviceName(TRUE));
        if(!file_exists($path))
            return FALSE;
        $result = array();
        $dir = new \DirectoryIterator($path);
        foreach($dir as $item) {
            if($item->isDot() || !$item->isLink())
                continue;
            $result[] = sprintf("/dev/%s", $item->getFilename());
        }
        return $result;
    }

    /**
     * Get detailed information about the container.
     * @return Detailed information about the container, FALSE on failure.
     */
    public function getDetail() {
        if($this->getData() === FALSE)
            return FALSE;
        return implode("\n", $this->headerInfo);
    }

    /**
     * How many key slots are used.
     * @return Number of used key slots, FALSE on failure.
     */
    public function getUsedKeySlots() {
        if($this->getData() === FALSE)
            return FALSE;
        return $this->usedKeySlots;
    }

    /**
     * How many key slots are unused.
     * @return Number of free key slots, FALSE on failure.
     */
    public function getFreeKeySlots() {
        if($this->getData() === FALSE)
            return FALSE;
        return $this->freeKeySlots;
    }

    /**
     * Get the UUID of the container.
     * @return The UUID of the container, FALSE on failure.
     */
    public function getUuid() {
        if($this->getData() === FALSE)
            return FALSE;
        return $this->uuid;
    }

    /**
     * Is the container open? (i.e. unlocked and mapped).
     * @return TRUE if the container is open, otherwise FALSE.
     */
    public function isOpen() {
        if($this->getData() === FALSE)
            return FALSE;
        return $this->isOpen;
    }

    /**
     * Get the devicefile of the mapped device (i.e. the open container).
     * @return The mapped devicefile of the container, FALSE on failure.
     */
    public function getDecryptedDeviceFile() {
        if($this->getData() === FALSE)
            return FALSE;
        return $this->deviceMapperDeviceFile;
    }

    /**
     * Get the device name of the mapped device (i.e. the open container).
     * @return The mapped device name of the container, FALSE on failure.
     */
    public function getDecryptedName() {
        if($this->getData() === FALSE)
            return FALSE;
        return $this->deviceMapperName;
    }

    /**
     * Helper function for determining a name for the decrypted device.
     * Avoids naming problems with, e.g. LUKS-on-LVM where the devicefile
     * is of the form /dev/mapper/VG-LV.
     * @return A sanitised string for use as the mapped device name.
     */
    private function generateDecryptedName() {
        $dev = $this->getDeviceName();
        $dev = preg_replace("/^mapper\//", "", $dev);
        return str_replace("/", "-", $dev);
    }

    /**
     * Get the description of the LUKS container.
     * @return The LUKS container description, FALSE on failure.
     */
    public function getDescription() {
        if ($this->getData() === FALSE)
            return FALSE;
        return sprintf(gettext("LUKS encrypted device %s[%s, %s]"),
                        ($this->getModel()) ? '('.$this->getModel().') ' : '',
                        $this->getDeviceFile(),
                        binary_format($this->getSize()));
    }

    /**
     * Create the container.
     * @param devicefile The device file where to create the LUKS container.
     * @param key A passphrase or key file (see following)
     * @param keyIsFile Optional. A boolean indicating whether the param 'key'
     *                  is a passphrase (FALSE, in which case key is a string),
     *                  or a key file (TRUE, in which case key is a filepath to
     *                  the key file). Defaults to FALSE.
     * @return TRUE if successful, otherwise FALSE.
     */
    public function create($key, $keyIsFile=FALSE) {
        switch($keyIsFile) {
            case TRUE:
                $cmd = sprintf("export LANG=C; cryptsetup luksFormat %s ".
                            "--key-file %s 2>&1",
                            escapeshellarg($this->getDeviceFile()),
                            escapeshellarg($key));
                break;
            case FALSE:
            default:
                $cmd = sprintf("export LANG=C; echo -n %s | ".
                            "cryptsetup luksFormat %s --key-file=- 2>&1",
                            escapeshellarg($key),
                            escapeshellarg($this->getDeviceFile()));
        }
        $process = new Process($cmd);
        $process->execute($output);
        $this->refresh();
        return TRUE;
    }

    /**
     * Remove the container.
     * @return TRUE if successful, otherwise FALSE.
     */
    public function remove() {
        // First, close the device if it is open
        if ($this->isOpen()) {
            if (FALSE === $luks->close()) {
                return FALSE;
            }
        }
        // Get the payload offset (header size)
        $cmd = sprintf("export LANG=C; cryptsetup luksDump %s ".
                        "| grep 'Payload offset' | awk '{print $3}'",
                        escapeshellarg($this->getDeviceFile()));

        $process = new Process($cmd);
        $process->setQuiet();
        $process->execute($output,$result);
        if (0 !== $result) {
            $header_size = 4096;
        } else {
            $header_size = trim($output[0]);
        }
        unset($cmd, $output, $result);

        // Get the storage device object.
        $sd = \OMV\System\Storage\StorageDevice::getStorageDevice($this->getDeviceFile());
        if (is_null($sd) || !$sd->exists()) {
            throw new \OMV\Exception("No storage device for %s",$this->getDeviceFile());
        }
        // Get the storage device backend of the given device.
        $mngr = \OMV\System\Storage\Backend\Manager::getInstance();
        $sdb = $mngr->getBackend($sd->getDeviceFile());
        if (is_null($sdb)) {
            throw new \OMV\Exception("No storage backend for %s",$this->getDeviceFile());
        }
        switch ($sdb->getType()) {
        case OMV_STORAGE_DEVICE_TYPE_SOFTWARERAID:
        case OMV_STORAGE_DEVICE_TYPE_DEVICEMAPPER:
            // Wipe existing filesystems.
            $cmd = sprintf("export LANG=C; wipefs -a %s 2>&1",
                            escapeshellarg($sd->getDeviceFile()));
            $process = new Process($cmd);
            $process->execute($output,$result);
            break;
        default:
            // Wipe existing filesystems.
            $cmd = sprintf("export LANG=C; sgdisk --zap-all %s 2>&1",
                            escapeshellarg($sd->getDeviceFile()));
            $process = new Process($cmd);
            $process->execute($output,$result);
            break;
        }
        unset($cmd, $output, $result);
        // Destroy the header by overwriting it
        $cmd = sprintf("export LANG=C; dd if=/dev/urandom ".
                        "of=%s bs=512 count=%s 2>&1",
                        escapeshellarg($sd->getDeviceFile()),
                        escapeshellarg($header_size));
        $process = new Process($cmd);
        $process->execute($output,$result);
        $this->refresh();
        return TRUE;
    }

    /**
     * Open (unlock) the container.
     * @param key A passphrase or key file (see following) which will unlock
     *            the LUKS container.
     * @param keyIsFile Optional. A boolean indicating whether the param 'key'
     *                  is a passphrase (FALSE, in which case key is a string),
     *                  or a key file (TRUE, in which case key is a filepath to
     *                  the key file). Defaults to FALSE.
     * @return TRUE if successful, otherwise FALSE.
     * TODO: change from using [dev]-crypt as the mapper name to the UUID of
     *       container instead (unique, probably will be needed for crypttab)
     */
    public function open($key, $keyIsFile=FALSE) {
        switch($keyIsFile) {
            case TRUE:
                $cmd = sprintf("export LANG=C; cryptsetup luksOpen %s ".
                            "%s-crypt --key-file %s 2>&1",
                            escapeshellarg($this->getDeviceFile()),
                            escapeshellarg($this->generateDecryptedName()),
                            escapeshellarg($key));
                break;
            case FALSE:
            default:
                $cmd = sprintf("export LANG=C; echo -n %s | ".
                            "cryptsetup luksOpen %s %s-crypt --key-file=- 2>&1",
                            escapeshellarg($key),
                            escapeshellarg($this->getDeviceFile()),
                            escapeshellarg($this->generateDecryptedName()));
        }
        $process = new Process($cmd);
        $process->execute($output,$result);
        $this->refresh();
        return TRUE;
    }

    /**
     * Close (lock) the container.
     * @return TRUE if successful, otherwise FALSE.
     */
    public function close() {
        $cmd = sprintf("export LANG=C; cryptsetup luksClose %s 2>&1",
                        escapeshellarg($this->getDecryptedName()));
        $process = new Process($cmd);
        $process->execute($output,$result);
        $this->refresh();
        return TRUE;
    }

    /**
     * Add a key to the container.
     * @param old A passphrase or key file (see following) that unlocks the device.
     * @param new A passphrase or key file (see following) to add to the device.
     * @param oldIsFile Optional. A boolean indicating whether the param 'old'
     *                  is a passphrase (FALSE, in which case old is a string),
     *                  or a key file (TRUE, in which case old is a filepath to
     *                  the key file). Defaults to FALSE.
     * @param newIsFile Optional. A boolean indicating whether the param 'new'
     *                  is a passphrase (FALSE, in which case new is a string),
     *                  or a key file (TRUE, in which case new is a filepath to
     *                  the key file). Defaults to FALSE.
     * @return TRUE if successful, otherwise FALSE.
     */
    public function addKey($old,
                           $new,
                           $oldIsFile=FALSE,
                           $newIsFile=FALSE) {
        // Build command line
        $cmd = "export LANG=C; ";
        switch($oldIsFile) {
            case TRUE:
                $cmd .= sprintf("cryptsetup luksAddKey -q ".
                            "%s --key-file %s ",
                            escapeshellarg($this->getDeviceFile()),
                            escapeshellarg($old));
                break;
            case FALSE:
            default:
                $cmd .= sprintf("echo -n %s | cryptsetup luksAddKey -q ".
                            " %s --key-file=- ",
                            escapeshellarg($old),
                            escapeshellarg($this->getDeviceFile()));
        }
        switch($newIsFile) {
            case TRUE:
                $cmd .= sprintf("%s 2>&1", escapeshellarg($new));
                break;
            case FALSE:
            default:
                $cmd .= sprintf("<(echo -n %s) 2>&1", escapeshellarg($new));
        }
        // N.B. Need to use bash rather than default sh here for
        // process substitution method of injecting new passphrase
        if(FALSE === $newIsFile)
            $cmd = "/bin/bash -c '".$cmd."'";
        $process = new Process($cmd);
        $process->execute($output,$result);
        $this->refresh();
        return TRUE;
    }

    /**
     * Change a key that unlocks the container.
     * @param old A passphrase or key file (see following) that unlocks the device.
     * @param new The passphrase or key file (see following) to replace the old one.
     * @param oldIsFile Optional. A boolean indicating whether the param 'old'
     *                  is a passphrase (FALSE, in which case old is a string),
     *                  or a key file (TRUE, in which case old is a filepath to
     *                  the key file). Defaults to FALSE.
     * @param newIsFile Optional. A boolean indicating whether the param 'new'
     *                  is a passphrase (FALSE, in which case new is a string),
     *                  or a key file (TRUE, in which case new is a filepath to
     *                  the key file). Defaults to FALSE.
     * @return TRUE if successful, otherwise FALSE.
     */
    public function changeKey($old,
                              $new,
                              $oldIsFile=FALSE,
                              $newIsFile=FALSE) {
        // Build command line
        $cmd = "export LANG=C; ";
        switch($oldIsFile) {
            case TRUE:
                $cmd .= sprintf("cryptsetup luksChangeKey -q ".
                            "%s --key-file %s ",
                            escapeshellarg($this->getDeviceFile()),
                            escapeshellarg($old));
                break;
            case FALSE:
            default:
                $cmd .= sprintf("echo -n %s | cryptsetup luksChangeKey -q ".
                            " %s --key-file=- ",
                            escapeshellarg($old),
                            escapeshellarg($this->getDeviceFile()));
        }
        switch($newIsFile) {
            case TRUE:
                $cmd .= sprintf("%s 2>&1", escapeshellarg($new));
                break;
            case FALSE:
            default:
                $cmd .= sprintf("<(echo -n %s) 2>&1", escapeshellarg($new));
        }
        // N.B. Need to use bash rather than default sh here for
        // process substitution method of injecting new passphrase
        if(FALSE === $newIsFile)
            $cmd = "/bin/bash -c '".$cmd."'";
        // Execute
        $process = new Process($cmd);
        $process->execute($output,$result);
        $this->refresh();
        return TRUE;
    }

    /**
     * Remove a key from the container.
     * @param key The passphrase or key file (see following) to remove.
     * @param keyIsFile Optional. A boolean indicating whether the param 'key'
     *                  is a passphrase (FALSE, in which case key is a string),
     *                  or a key file (TRUE, in which case key is a filepath to
     *                  the key file). Defaults to FALSE.
     * @return TRUE if successful, otherwise FALSE.
     */
    public function removeKey($key, $keyIsFile=FALSE) {
        switch($keyIsFile) {
            case TRUE:
                $cmd = sprintf("export LANG=C; cryptsetup luksRemoveKey -q ".
                            "%s --key-file %s 2>&1",
                            escapeshellarg($this->getDeviceFile()),
                            escapeshellarg($key));
                break;
            case FALSE:
            default:
                $cmd = sprintf("/bin/bash -c 'export LANG=C; echo -n %s | ".
                            "cryptsetup luksRemoveKey -q %s --key-file=- 2>&1'",
                            escapeshellarg($key),
                            escapeshellarg($this->getDeviceFile()));
        }
        $process = new Process($cmd);
        $process->execute($output,$result);
        $this->refresh();
        return TRUE;
    }

    /**
     * Erase (kill) a key slot - remove a key from the
     * container without knowing it (cf. removeKey)
     * @param slot A number from 0-7 representing which key slot to erase
     * @return TRUE if successful, otherwise FALSE.
     */
    public function killSlot($slot) {
        // Use batch mode to avoid needing a key - note this
        // makes it trivial to kill the last slot without warning!
        $cmd = sprintf("export LANG=C; cryptsetup -q luksKillSlot %s %s 2>&1",
                        escapeshellarg($this->getDeviceFile()),
                        escapeshellarg($slot));
        $process = new Process($cmd);
        $process->execute($output,$result);
        $this->refresh();
        return TRUE;
    }

    /**
     * Test whether a key will open the container.
     * @param key A passphrase or key file (see following) to test.
     * @param keyIsFile Optional. A boolean indicating whether the param 'key'
     *                  is a passphrase (FALSE, in which case key is a string),
     *                  or a key file (TRUE, in which case key is a filepath to
     *                  the key file). Defaults to FALSE.
     * @return An integer from 0-7 representing which key slot the
     *         key matched (unlocked), otherwise FALSE.
     */
    public function testKey($key, $keyIsFile=FALSE) {
        // Check what version of cryptsetup is installed to determine
        // if the --test-passphrase argument is supported or not.
        $cmd = "export LANG=C; cryptsetup --version 2>&1";
        $process = new Process($cmd);
        $process->execute($output,$result);
        $cryptsetupVersion = str_replace("cryptsetup ", "", $output[0]);
        $hasTestPassphrase = version_compare($cryptsetup_version, "1.5.0", ">=");
        unset($cmd, $output, $result);
        // Decide which codepath to use.
        if(TRUE === $hasTestPassphrase) {
            switch($keyIsFile) {
                case TRUE:
                    $cmd = sprintf("export LANG=C; cryptsetup luksOpen -v ".
                                "--test-passphrase %s --key-file %s 2>&1",
                                escapeshellarg($this->getDeviceFile()),
                                escapeshellarg($key));
                    break;
                case FALSE:
                default:
                    $cmd = sprintf("/bin/bash -c 'export LANG=C; echo -n %s ".
                                "| cryptsetup luksOpen -v --test-passphrase %s ".
                                "--key-file=- 2>&1'",
                                escapeshellarg($key),
                                escapeshellarg($this->getDeviceFile()));
            }
            $validCodes = array(0);
        } else {
            // If the '--test-passphrase' argument is not available, use a
            // workaround where we open the device (read only) with a temporary
            // name and then close it later. If the device is already open, this
            // fails with error code 5 (device already open or busy), but will
            // still report which slot was unlocked if key is valid.
            $tempName = uniqid("luksTest_");
            switch($keyIsFile) {
                case TRUE:
                    $cmd = sprintf("export LANG=C; cryptsetup luksOpen -r -v ".
                                "%s %s --key-file %s 2>&1",
                                escapeshellarg($this->getDeviceFile()),
                                escapeshellarg($tempName),
                                escapeshellarg($key));
                    break;
                case FALSE:
                default:
                    $cmd = sprintf("/bin/bash -c 'export LANG=C; echo -n %s ".
                                "| cryptsetup luksOpen -r -v %s %s ".
                                "--key-file=- 2>&1'",
                                escapeshellarg($key),
                                escapeshellarg($this->getDeviceFile()),
                                escapeshellarg($tempName));
            }
            $validCodes = array(0,5);
        }
        // Test the key and get the key slot number if successful
        $process = new Process($cmd);
        $tmp = $process->execute($out, $result);
        if(!in_array($result, $validCodes)) {
            throw new \OMV\Exception($output);
        }
        $slot = explode(" ",
                        array_shift(
                            preg_grep("/^Key slot \d unlocked.$/", $output)
                        )
                )[2];
        // If we actually opened the device, under a temporary name, close it.
        if (FALSE === $hasTestPassphrase) {
            if($result === 0 && $this->getDecryptedName() == $tempName)
                $this->close();
        }
        // Return which key slot was unlocked.
        return $slot;
    }

    /**
     * Backup the header for the container.
     * @param filepath The filename to write the header backup to.
     * @return TRUE if successful, otherwise FALSE.
     */
    public function backupHeader($filepath) {
        $cmd = sprintf("export LANG=C; cryptsetup luksHeaderBackup ".
                        "%s --header-backup-file %s 2>&1",
                escapeshellarg($this->getDeviceFile()),
                escapeshellarg($filepath));
        $process = new Process($cmd);
        $process->execute($output,$result);
        return TRUE;
    }

    /**
     * Restore the header for the container from a backup.
     * @param filepath The path to the header backup file to restore.
     * @return TRUE if successful, otherwise FALSE.
     */
    public function restoreHeader($filepath) {
        $cmd = sprintf("export LANG=C; cryptsetup luksHeaderRestore -q ".
                        "%s --header-backup-file %s 2>&1",
                escapeshellarg($this->getDeviceFile()),
                escapeshellarg($filepath));
        $process = new Process($cmd);
        $process->execute($output,$result);
        $this->refresh();
        return TRUE;
    }
}