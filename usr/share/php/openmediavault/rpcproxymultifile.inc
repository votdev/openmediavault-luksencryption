<?php
/**
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
require_once("openmediavault/rpcproxy.inc");


/**
 * A specialized RPC proxy that handles multiple file uploads.
 */
class OMVUploadMultiFileRpcProxy extends OMVUploadRpcProxy {
    protected $paramsSchema = '{
        "type":"object",
        "properties":{
            "service":{"type":"string"},
            "method":{"type":"string"},
            "params":{"type":"any"},
            "options":{"type":"object","optional":true},
            "MAX_FILE_SIZE":{"type":"any", "optional":true}
        }
    }';

    private function codeToMessage($code) {
        switch ($code) {
            case UPLOAD_ERR_INI_SIZE:
                $message = "The uploaded file exceeds the upload_max_filesize directive in php.ini";
                break;
            case UPLOAD_ERR_FORM_SIZE:
                $message = "The uploaded file exceeds the maximum size allowed";
                break;
            case UPLOAD_ERR_PARTIAL:
                $message = "The uploaded file was only partially uploaded";
                break;
            case UPLOAD_ERR_NO_FILE:
                $message = "No file was uploaded";
                break;
            case UPLOAD_ERR_NO_TMP_DIR:
                $message = "The system temporary folder is missing";
                break;
            case UPLOAD_ERR_CANT_WRITE:
                $message = "Failed to write file to disk";
                break;
            case UPLOAD_ERR_EXTENSION:
                $message = "File upload stopped by extension";
                break;

            default:
                $message = "Unknown upload error";
                break;
        }
        return $message;
    }

    /**
     * Check the uploaded files. Append the filenames
     * to the RPC service method parameters.
     * @throw E_MISC_FAILURE
     */
    protected function preExecute() {
        // Are the file(s) successfully uploaded?
        foreach($_FILES as $key => $file) {
            if(!in_array($file['error'],
                array(UPLOAD_ERR_OK, UPLOAD_ERR_NO_FILE))) {
                throw new OMVException( OMVErrorMsg::E_MISC_FAILURE,
                    $this->codeToMessage($file['error']));
            }
            if($file['error']===UPLOAD_ERR_OK &&
                !is_uploaded_file($file['tmp_name'])) {
                throw new OMVException( OMVErrorMsg::E_MISC_FAILURE,
                    "Invalid upload request.");
            }
            // Modify the service method parameters.
            if($file['error']===UPLOAD_ERR_OK)
                $this->params['params'][$key] = $file['tmp_name'];
        }
    }

    /**
     * The function that is called after the RPC has been successfully
     * executed or it has been failed.
     */
    public function cleanup() {
        $this->secureCleanup();
    }

    /**
     * Remove files using shred.
     */
    public function secureCleanup() {
        foreach($_FILES as $key => $file) {
            $cmdTemplate = "export LANG=C; shred -u %s ";
            if($file['error']===UPLOAD_ERR_OK &&
                is_uploaded_file($file['tmp_name'])) {
                $cmd = sprintf($cmdTemplate, escapeshellarg($file['tmp_name']));
                @OMVUtil::exec($cmd, $output, $result);
                if ($result !== 0) {
                    $this->debug($output);
                    // fall back to PHP deletion
                    if(file_exists($file['tmp_name']))
                        unlink($file['tmp_name']);
                }
                unset($cmd, $output, $result);
            }
        }
    }
}
