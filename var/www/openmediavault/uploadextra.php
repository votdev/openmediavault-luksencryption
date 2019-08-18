<?php
/**
 *
 * @license   http://www.gnu.org/licenses/gpl.html GPL Version 3
 * @author    Volker Theile <volker.theile@openmediavault.org>
 * @author    OpenMediaVault Plugin Developers <plugins@omv-extras.org>
 * @copyright Copyright (c) 2009-2015 Volker Theile
 * @copyright Copyright (c) 2015-2019 OpenMediaVault Plugin Developers
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
try {
    function exception_error_handler($errno, $errstr, $errfile, $errline) {
        switch ($errno) {
        case E_STRICT:
            break;
        default:
            throw new \ErrorException($errstr, 0, $errno, $errfile, $errline);
            break;
        }
    }
    set_error_handler("exception_error_handler");

    require_once("openmediavault/autoloader.inc");
    require_once("openmediavault/env.inc");

    $session = &\OMV\Session::getInstance();
    $session->start();
    $session->validate();

    $server = new \OMV\Rpc\Proxy\UploadExtras(); // Use custom extended upload handler
    $server->handle();
    $server->cleanup();
} catch(\Exception $e) {
    if (isset($server))
        $server->cleanup();
    header("Content-Type: text/html");
    print json_encode_safe(array(
        "success" => false, // required by ExtJS
        "responseText" => $e->getMessage(), // required by ExtJS
        "errors" => null, // required by ExtJS
        "code" => $e->getCode(),
        "message" => $e->getMessage(),
        "trace" => $e->__toString()
    ));
}
?>
