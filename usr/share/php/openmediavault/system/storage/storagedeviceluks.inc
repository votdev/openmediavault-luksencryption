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
namespace OMV\System\Storage;

/**
 * Class for handling an open LUKS container,
 * i.e. from the decrypted device point of view.
 */
class Luks extends StorageDevice {

    /**
     * Get the underlying device model.
     * @return The device model, otherwise an empty string.
     */
    public function getModel() {
        if(FALSE === ($luks = $this->getContainer()))
            return "";
        return $luks->getModel();
    }

    /**
     * Get the description of the LUKS container.
     * @return The LUKS container description, FALSE on failure.
     */
    public function getDescription() {
        return sprintf(gettext("LUKS encrypted container on %s %s[%s, %s]"),
                        $this->getCanonicalLuksEncryptedDeviceFile(),
                        ($this->getModel()) ? '('.$this->getModel().') ' : '',
                        $this->getDeviceFile(),
                        binary_format($this->getSize()));
    }
}
