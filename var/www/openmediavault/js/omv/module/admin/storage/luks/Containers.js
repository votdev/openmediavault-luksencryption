/**
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
// require("js/omv/WorkspaceManager.js")
// require("js/omv/workspace/grid/Panel.js")
// require("js/omv/workspace/window/Form.js")
// require("js/omv/workspace/window/Grid.js")
// require("js/omv/workspace/window/plugin/ConfigObject.js")
// require("js/omv/Rpc.js")
// require("js/omv/data/Store.js")
// require("js/omv/data/Model.js")
// require("js/omv/data/proxy/Rpc.js")
// require("js/omv/data/Download.js")
// require("js/omv/window/Window.js")
// require("js/omv/form/Panel.js")
// require("js/omv/util/Format.js")
// require("js/omv/window/Execute.js")
// require("js/omv/workspace/window/TextArea.js")

/**
 * @class OMV.module.admin.storage.luks.container.Create
 * @derived OMV.workspace.window.Form
 */
Ext.define("OMV.module.admin.storage.luks.container.Create", {
    extend: "OMV.workspace.window.Form",
    requires: [
        "OMV.data.Store",
        "OMV.data.Model",
        "OMV.data.proxy.Rpc"
    ],

    title: _("Create encrypted device"),
    okButtonText: _("Create"),
    submitMsg: _("Creating encrypted device ..."),
    keyFileUrl: "uploadextra.php",
    options: {
        secureDeletion: true
    },
    hideResetButton: true,
    width: 540,
    rpcService: "LuksMgmt",
    rpcSetMethod: "createContainer",
    plugins: [{
        ptype: "linkedfields",
        correlations: [{
            name: [ "keyfile" ],
            conditions: [
                { name: "unlockatboot", value: true }
            ],
            properties: [
                "!allowBlank"
            ]
        },{
            name: [ "passphrase" ],
            conditions: [
                { name: "unlockatboot", value: true }
            ],
            properties: [
                "readOnly",
                "!submitValue"
            ]
        },{
            name: [ "passphraseconf" ],
            conditions: [
                { name: "unlockatboot", value: true }
            ],
            properties: [
                "readOnly"
            ]
        }]
    }],

    constructor: function() {
        var me = this;
        me.callParent(arguments);
    },

    getFormConfig: function() {
        return {
            layout: {
                type: "vbox",
                align: "stretch"
            }
        };
    },

    initComponent: function() {
        var me = this;
        me.callParent(arguments);
        me.on("show", function() {
                       // Set focus to field 'Passphrase'.
                       var field = me.fp.findField("passphrase");
                       if (!Ext.isEmpty(field))
                               field.focus(false, 500);
               }, me);
    },

    getFormItems: function() {
        var me = this;
        return [{
            xtype: "combo",
            name: "devicefile",
            fieldLabel: _("Device"),
            emptyText: _("Select a device ..."),
            store: Ext.create("OMV.data.Store", {
                autoLoad: true,
                model: OMV.data.Model.createImplicit({
                    idProperty: "devicefile",
                    fields: [
                        { name: "devicefile", type: "string" },
                        { name: "description", type: "string" }
                    ]
                }),
                proxy: {
                    type: "rpc",
                    appendSortParams: false,
                    rpcData: {
                        service: "LuksMgmt",
                        method: "getContainerCandidates"
                    }
                },
                sorters: [{
                    direction: "ASC",
                    property: "devicefile"
                }]
            }),
            displayField: "description",
            valueField: "devicefile",
            allowBlank: false,
            editable: false,
            triggerAction: "all"
        },{
            xtype: "fieldset",
            title: _("Enter a passphrase or upload a key file"),
            defaults: {
                labelSeparator: ""
            },
            items: [{
                xtype: "passwordfield",
                name: "passphrase",
                fieldLabel: _("Passphrase"),
                allowBlank: true,
                triggerAction: "all",
                listeners: {
                    scope: me,
                    specialkey: me.submitOnEnter
                }
            },{
                xtype: "passwordfield",
                name: "passphraseconf",
                fieldLabel: _("Confirm passphrase"),
                allowBlank: true,
                submitValue: false,
                listeners: {
                    scope: me,
                    specialkey: me.submitOnEnter
                }
            },{
                xtype: "hiddenfield",
                name: "MAX_FILE_SIZE",
                value: 8388608
            },{
                xtype: "filefield",
                name: "keyfile",
                fieldLabel: _("Key file"),
                buttonText: _("Browse..."),
                allowBlank: true,
                listeners: {
                    scope: me,
                    specialkey: me.submitOnEnter
                }
            }]
        },{
            xtype: "checkbox",
            name: "unlockatboot",
            fieldLabel: _("Unlock at boot"),
            checked: false,
            inputValue: 1,
            uncheckedValue: 0,
            submitValue: true,
            boxLabel: _("Automatically unlock the container on startup. Requires a key file.")
        }];
    },

    /**
     * Custom form validation function to allow
     * only one of passphrase or key file
     */
    isValid: function() {
        var me = this;
        this.clearInvalid();
        // call standard isValid() from parent class
        var pValid = me.callParent(arguments);
        // check whether boot-time unlock is enabled,
        // if yes then don't need to do any more here
        var crypttab = me.findField("unlockatboot");
        if (!crypttab.value) {
            // Check this form, only one of passphrase or key file
            var nValid = false;
            var passphrase = me.findField("passphrase");
            var passphrase2 = me.findField("passphraseconf");
            var keyfile = me.findField("keyfile");
            if((passphrase.value == "" && keyfile.value) ||
                (passphrase.value != "" && !keyfile.value))
                nValid = true;
            if(!nValid) {
                if(passphrase.value == "" && !keyfile.value)
                    var msg = _("Either a passphrase or a key file is required");
                else if(passphrase.value != "" && keyfile.value)
                    var msg = _("Use either a passphrase or a key file – not both");
                this.markInvalid([
                    { id: "passphrase", msg: msg },
                    { id: "passphraseconf", msg: msg },
                    { id: "keyfile", msg: msg }
                ]);
            } else {
                passphrase.clearInvalid();
                passphrase2.clearInvalid();
                keyfile.clearInvalid();
                // Check the passphrases match
                var values = me.getValues();
                var field = me.findField("passphraseconf");
                if (values.passphrase !== field.getValue()) {
                    var msg = _("Passphrases don't match");
                    this.markInvalid([
                        { id: "passphrase", msg: msg },
                        { id: "passphraseconf", msg: msg }
                    ]);
                    nValid = false;
                }
            }
            // Final return - both this custom isValid() and standard
            // isValid() from parent must be true to return true.
            if(pValid && nValid)
                return true;
            else
                return false;
        } else {
            return pValid;
        }
    },

    onOkButton: function() {
        var me = this;
        var basicForm = me.fp.getForm();
        if(!this.isValid())
            return;
        OMV.MessageBox.show({
            title: _("Confirmation"),
            msg: _("Do you really want to encrypt this device? Any existing data on it will be deleted."),
            buttons: Ext.Msg.YESNO,
            fn: function(answer) {
                if(answer === "no")
                    return;
                me.doSubmit.call(me);
            },
            scope: me,
            icon: Ext.Msg.QUESTION
        });
    },

    doSubmit: function() {
        var me = this;
        // What kind of key are we using, key file or passphrase?
        if(me.fp.findField("keyfile").value) {
            me.doUpload();
        } else {
            me.fp.findField("MAX_FILE_SIZE").submitValue = false;
            me.callParent(arguments);
        }
    },

    doUpload: function() {
        var me = this;
        var basicForm = me.fp.getForm();
        me.setLoading(me.submitMsg);
        basicForm.submit({
            url: me.keyFileUrl,
            method: "POST",
            params: {
                service: me.rpcService,
                method: me.rpcSetMethod,
                params: !Ext.isEmpty(me.params) ? Ext.JSON.encode(
                  me.params).htmlspecialchars() : me.params,
                options: !Ext.isEmpty(me.options) ? Ext.JSON.encode(
                  me.options).htmlspecialchars() : me.options
            },
            scope: me,
            success: function(form, action) {
                me.setLoading(false);
                this.onUploadSuccess(form, action);
            },
            failure: function(form, action) {
                me.setLoading(false);
                this.onUploadFailure(form, action);
            }
        });
    },

    submitOnEnter: function(field, event) {
        var me = this;
        if (event.getKey() == event.ENTER) {
            me.onOkButton.call(me);
        }
    },

    /**
     * Method that is called when the file upload was successful.
     * @param form The form that requested the action.
     * @param action The Action object which performed the operation.
     */
    onUploadSuccess: function(form, action) {
        var me = this;
        var retVal = action.result.responseText;
        // !!! Attention !!! Fire event before window is closed,
        // otherwise the dialog's own listener is removed before the
        // event has been fired and the action has been executed.
        // Fire 'submit' instead of success to duplicate that from
        // passphrase method, which doesn't do any uploading.
        me.fireEvent("submit", me, retVal);
        // Now close the dialog.
        me.close();
    },

    /**
     * Method that is called when the file upload has been failed.
     * @param form The form that requested the action.
     * @param action The Action object which performed the operation.
     */
    onUploadFailure: function(form, action) {
        var msg = action.response.responseText;
        try {
            // Try to decode JSON error messages.
            msg = Ext.JSON.decode(msg);
            // Format the message text for line breaks.
            msg.message = this.nl2br(msg.message);
        } catch(e) {
            // Error message is plain text, e.g. error message from the
            // web server.
        }
        OMV.MessageBox.error(null, msg);
    },

    /**
     * Helper function to insert line breaks back into the error message
     * @param str The message to process for line breaks.
     * @param is_xhtml Boolean, whether to insert XHTML-compatible <br/>
     *                 tags or not (default is true).
     */
    nl2br: function(str, is_xhtml) {
        var breakTag = (is_xhtml || typeof is_xhtml === 'undefined') ? '<br />' : '<br>';
        return (str + '').replace(/([^>\r\n]?)(\r\n|\n\r|\r|\n)/g, '$1' + breakTag + '$2');
    }
});


/**
 * Generalized class for providing a single key - used to
 * unlock a device, test if a key works, or to remove a key.
 * @class OMV.module.admin.storage.luks.container.SingleKey
 * @derived OMV.workspace.window.Form
 * @param uuid The UUID of the configuration object.
 * @param devicefile The device file, e.g. /dev/sda.
 */
Ext.define("OMV.module.admin.storage.luks.container.SingleKey", {
    extend: "OMV.workspace.window.Form",

    rpcService: "LuksMgmt",
    // rpcSetMethod: "openContainer", // override
    // title: _("Unlock encrypted device"), //override
    // okButtonText: _("Unlock"), // override
    // submitMsg: _("Unlocking ..."), //override
    keyFileUrl: "uploadextra.php",
    options: {
        secureDeletion: true
    },
    autoLoadData: false,
    hideResetButton: true,
    width: 540,

    constructor: function() {
        var me = this;
        me.callParent(arguments);
    },

    getFormConfig: function() {
        return {
            layout: {
                type: "vbox",
                align: "stretch"
            }
        };
    },

    getFormItems: function() {
        var me = this;
        return [{
            xtype: "textfield",
            name: "devicefile",
            fieldLabel: _("Device"),
            allowBlank: false,
            readOnly: true,
            submitValue: false,
            value: me.params.devicefile,
            listeners: {
                scope: me,
                specialkey: me.submitOnEnter
            }
        },{
            xtype: "fieldset",
            title: _("Enter a passphrase or upload a key file"),
            defaults: {
                labelSeparator: ""
            },
            items: [{
                xtype: "passwordfield",
                name: "passphrase",
                fieldLabel: _("Passphrase"),
                allowBlank: true,
                listeners: {
                    scope: me,
                    specialkey: me.submitOnEnter
                }
            },{
                xtype: "hiddenfield",
                name: "MAX_FILE_SIZE",
                value: 8388608
            },{
                xtype: "filefield",
                name: "keyfile",
                fieldLabel: _("Key file"),
                buttonText: _("Browse..."),
                allowBlank: true,
                listeners: {
                    scope: me,
                    specialkey: me.submitOnEnter
                }
            }]
        }];
    },

    initComponent: function() {
        var me = this;
        me.callParent(arguments);
        me.on("show", function() {
                       // Set focus to field 'Passphrase'.
                       var field = me.fp.findField("passphrase");
                       if (!Ext.isEmpty(field))
                               field.focus(false, 500);
               }, me);
    },

    /**
     * Custom form validation function to allow
     * only one of passphrase or key file
     */
    isValid: function() {
        var me = this;
        var pValid = me.callParent(arguments);
        var valid = false;
        var passphrase = me.findField("passphrase");
        var keyfile = me.findField("keyfile");
        if((passphrase.value == "" && keyfile.value) ||
            (passphrase.value != "" && !keyfile.value))
            valid = true;
        if(!valid) {
            if(passphrase.value == "" && !keyfile.value)
                var msg = _("Either a passphrase or a key file is required");
            else if(passphrase.value != "" && keyfile.value)
                var msg = _("Use either a passphrase or a key file – not both");
            this.markInvalid([
                { id: "passphrase", msg: msg },
                { id: "keyfile", msg: msg }
            ]);
        } else {
            passphrase.clearInvalid();
            keyfile.clearInvalid();
        }
        if(valid && pValid)
            return true;
        else
            return false;
    },

    getRpcSetParams: function() {
        var me = this;
        var params = me.callParent(arguments);
        return Ext.apply(params, {
            uuid: me.params.uuid,
            devicefile: me.params.devicefile
        });
    },

    onOkButton: function() {
        var me = this;
        var basicForm = me.fp.getForm();
        if(!this.isValid())
            return;
        // Hook into this 'askconfirmation' event to display any confirmation
        // message needed. Typically return false from your function and use
        // the message window to call doSubmit() or quit as appropriate.
        if (me.fireEvent("askconfirmation", me) === false)
            return;
        me.doSubmit();
    },

    doSubmit: function() {
        var me = this;
        // What kind of key are we using, key file or passphrase?
        if(me.fp.findField("keyfile").value) {
            me.doUpload();
        } else {
            me.fp.findField("MAX_FILE_SIZE").submitValue = false;
            me.callParent(arguments);
        }
    },

    doUpload: function() {
        var me = this;
        var basicForm = me.fp.getForm();
        me.setLoading(me.submitMsg);
        basicForm.submit({
            url: me.keyFileUrl,
            method: "POST",
            params: {
                service: me.rpcService,
                method: me.rpcSetMethod,
                params: !Ext.isEmpty(me.params) ? Ext.JSON.encode(
                  me.params).htmlspecialchars() : me.params,
                options: !Ext.isEmpty(me.options) ? Ext.JSON.encode(
                  me.options).htmlspecialchars() : me.options
            },
            scope: me,
            success: function(form, action) {
                me.setLoading(false);
                this.onUploadSuccess(form, action);
            },
            failure: function(form, action) {
                me.setLoading(false);
                this.onUploadFailure(form, action);
            }
        });
    },

    submitOnEnter: function(field, event) {
        var me = this;
        if (event.getKey() == event.ENTER) {
            me.onOkButton.call(me);
        }
    },

    /**
     * Method that is called when the file upload was successful.
     * @param form The form that requested the action.
     * @param action The Action object which performed the operation.
     */
    onUploadSuccess: function(form, action) {
        var me = this;
        // when doing test function, this will be the key slot number:
        var retVal = action.result.responseText;
        // !!! Attention !!! Fire event before window is closed,
        // otherwise the dialog's own listener is removed before the
        // event has been fired and the action has been executed.
        // Fire 'submit' instead of success to duplicate that from
        // passphrase method, which doesn't do any uploading.
        me.fireEvent("submit", me, action.response, retVal);
        // Now close the dialog.
        me.close();
    },

    /**
     * Method that is called when the file upload has been failed.
     * @param form The form that requested the action.
     * @param action The Action object which performed the operation.
     */
    onUploadFailure: function(form, action) {
        var msg = action.response.responseText;
        try {
            // Try to decode JSON error messages.
            msg = Ext.JSON.decode(msg);
            // Format the message text for line breaks.
            msg.message = this.nl2br(msg.message);
        } catch(e) {
            // Error message is plain text, e.g. error message from the
            // web server.
        }
        OMV.MessageBox.error(null, msg);
    },

    /**
     * Helper function to insert line breaks back into the error message
     * @param str The message to process for line breaks.
     * @param is_xhtml Boolean, whether to insert XHTML-compatible <br/>
     *                 tags or not (default is true).
     */
    nl2br: function(str, is_xhtml) {
        var breakTag = (is_xhtml || typeof is_xhtml === 'undefined') ? '<br />' : '<br>';
        return (str + '').replace(/([^>\r\n]?)(\r\n|\n\r|\r|\n)/g, '$1' + breakTag + '$2');
    }
});


/**
 * Generalized class for providing two keys - used to add
 * or change a key.
 * @class OMV.module.admin.storage.luks.container.DualKey
 * @derived OMV.workspace.window.Form
 * @param uuid The UUID of the configuration object.
 * @param devicefile The device file, e.g. /dev/sda.
 */
Ext.define("OMV.module.admin.storage.luks.container.DualKey", {
    extend: "OMV.workspace.window.Form",

    rpcService: "LuksMgmt",
    // rpcSetMethod: "addContainerPassphrase", // override
    // title: _("Add passphrase"), // override
    // okButtonText: _("Add"), // override
    keyFileUrl: "uploadextra.php",
    options: {
        secureDeletion: true
    },
    autoLoadData: false,
    hideResetButton: true,
    width: 540,

    constructor: function() {
        var me = this;
        me.callParent(arguments);
    },

    initComponent: function() {
        var me = this;
        me.callParent(arguments);
        me.on("show", function() {
                       // Set focus to field 'Current passphrase'.
                       var field = me.fp.findField("oldpassphrase");
                       if (!Ext.isEmpty(field))
                               field.focus(false, 500);
               }, me);
    },

    getFormConfig: function() {
        var me = this;
        return {
            layout: {
                type: "vbox",
                align: "stretch"
            }
        };
    },

    getFormItems: function() {
        var me = this;
        return [{
            xtype: "textfield",
            name: "devicefile",
            fieldLabel: _("Device"),
            allowBlank: false,
            readOnly: true,
            submitValue: false,
            value: me.params.devicefile,
            listeners: {
                scope: me,
                specialkey: me.submitOnEnter
            }
        },{
            xtype: "hiddenfield",
            name: "MAX_FILE_SIZE",
            value: 8388608
        },{
            xtype: "fieldset",
            title: _("Enter an existing, valid passphrase or upload a key file that unlocks the device"),
            defaults: {
                labelSeparator: ""
            },
            items: [{
                xtype: "passwordfield",
                name: "oldpassphrase",
                fieldLabel: _("Current passphrase"),
                allowBlank: true,
                listeners: {
                    scope: me,
                    specialkey: me.submitOnEnter
                }
            },{
                xtype: "filefield",
                name: "oldkeyfile",
                fieldLabel: _("Current key file"),
                buttonText: _("Browse..."),
                allowBlank: true,
                listeners: {
                    scope: me,
                    specialkey: me.submitOnEnter
                }
            }]
        },{
            xtype: "fieldset",
            title: _("Enter the new passphrase or upload a key file"),
            defaults: {
                labelSeparator: ""
            },
            items: [{
                xtype: "passwordfield",
                name: "newpassphrase",
                fieldLabel: _("Passphrase"),
                allowBlank: true,
                triggerAction: "all",
                listeners: {
                    scope: me,
                    specialkey: me.submitOnEnter
                }
            },{
                xtype: "passwordfield",
                name: "newpassphraseconf",
                fieldLabel: _("Confirm passphrase"),
                allowBlank: true,
                submitValue: false,
                listeners: {
                    scope: me,
                    specialkey: me.submitOnEnter
                }
            },{
                xtype: "filefield",
                name: "newkeyfile",
                fieldLabel: _("Key file"),
                buttonText: _("Browse..."),
                allowBlank: true,
                listeners: {
                    scope: me,
                    specialkey: me.submitOnEnter
                }
            }]
        }];
    },

    /**
     * Custom form validation function to allow
     * only one of passphrase or key file
     */
    isValid: function() {
        var me = this;
        this.clearInvalid();
        // call standard isValid() from parent class
        var pValid = me.callParent(arguments);
        // Check this form, only one of old passphrase or key file
        var oValid = false;
        var passphrase = me.findField("oldpassphrase");
        var keyfile = me.findField("oldkeyfile");
        if((passphrase.value == "" && keyfile.value) ||
            (passphrase.value != "" && !keyfile.value))
            oValid = true;
        if(!oValid) {
            if(passphrase.value == "" && !keyfile.value)
                var msg = _("Either a passphrase or a key file is required");
            else if(passphrase.value != "" && keyfile.value)
                var msg = _("Use either a passphrase or a key file – not both");
            this.markInvalid([
                { id: "oldpassphrase", msg: msg },
                { id: "oldkeyfile", msg: msg }
            ]);
        } else {
            passphrase.clearInvalid();
            keyfile.clearInvalid();
        }
        // Check this form, only one of new passphrase or key file
        var nValid = false;
        var passphrase = me.findField("newpassphrase");
        var passphrase2 = me.findField("newpassphraseconf");
        var keyfile = me.findField("newkeyfile");
        if((passphrase.value == "" && keyfile.value) ||
            (passphrase.value != "" && !keyfile.value))
            nValid = true;
        if(!nValid) {
            if(passphrase.value == "" && !keyfile.value)
                var msg = _("Either a passphrase or a key file is required");
            else if(passphrase.value != "" && keyfile.value)
                var msg = _("Use either a passphrase or a key file – not both");
            this.markInvalid([
                { id: "newpassphrase", msg: msg },
                { id: "newpassphraseconf", msg: msg },
                { id: "newkeyfile", msg: msg }
            ]);
        } else {
            passphrase.clearInvalid();
            passphrase2.clearInvalid();
            keyfile.clearInvalid();
            // Check the (new) passphrases match
            var values = me.getValues();
            var field = me.findField("newpassphraseconf");
            if (values.newpassphrase !== field.getValue()) {
                var msg = _("Passphrases don't match");
                this.markInvalid([
                    { id: "newpassphrase", msg: msg },
                    { id: "newpassphraseconf", msg: msg }
                ]);
                nValid = false;
            }
        }
        // Final return - both this custom isValid() and standard
        // isValid() from parent must be true to return true.
        if(pValid && oValid && nValid)
            return true;
        else
            return false;
    },

    getRpcSetParams: function() {
        var me = this;
        var params = me.callParent(arguments);
        return Ext.apply(params, {
            uuid: me.params.uuid,
            devicefile: me.params.devicefile
        });
    },

    onOkButton: function() {
        var me = this;
        var basicForm = me.fp.getForm();
        if(!this.isValid())
            return;
        // Hook into this 'askconfirmation' event to display any confirmation
        // message needed. Typically return false from your function and use
        // the message window to call doSubmit() or quit as appropriate.
        if (me.fireEvent("askconfirmation", me) === false)
            return;
        me.doSubmit();
    },

    doSubmit: function() {
        var me = this;
        // What kind of key are we using, key file or passphrase?
        if(me.fp.findField("oldkeyfile").value ||
            me.fp.findField("newkeyfile").value) {
            me.doUpload();
        } else {
            me.fp.findField("MAX_FILE_SIZE").submitValue = false;
            me.callParent(arguments);
        }
    },

    doUpload: function() {
        var me = this;
        var basicForm = me.fp.getForm();
        me.setLoading(me.submitMsg);
        basicForm.submit({
            url: me.keyFileUrl,
            method: "POST",
            params: {
                service: me.rpcService,
                method: me.rpcSetMethod,
                params: !Ext.isEmpty(me.params) ? Ext.JSON.encode(
                  me.params).htmlspecialchars() : me.params,
                options: !Ext.isEmpty(me.options) ? Ext.JSON.encode(
                  me.options).htmlspecialchars() : me.options
            },
            scope: me,
            success: function(form, action) {
                me.setLoading(false);
                this.onUploadSuccess(form, action);
            },
            failure: function(form, action) {
                me.setLoading(false);
                this.onUploadFailure(form, action);
            }
        });
    },

    submitOnEnter: function(field, event) {
        var me = this;
        if (event.getKey() == event.ENTER) {
            me.onOkButton.call(me);
        }
    },

    /**
     * Method that is called when the file upload was successful.
     * @param form The form that requested the action.
     * @param action The Action object which performed the operation.
     */
    onUploadSuccess: function(form, action) {
        var me = this;
        var retVal = action.result.responseText;
        // !!! Attention !!! Fire event before window is closed,
        // otherwise the dialog's own listener is removed before the
        // event has been fired and the action has been executed.
        // Fire 'submit' instead of success to duplicate that from
        // passphrase method, which doesn't do any uploading.
        me.fireEvent("submit", me, retVal);
        // Now close the dialog.
        me.close();
    },

    /**
     * Method that is called when the file upload has been failed.
     * @param form The form that requested the action.
     * @param action The Action object which performed the operation.
     */
    onUploadFailure: function(form, action) {
        var msg = action.response.responseText;
        try {
            // Try to decode JSON error messages.
            msg = Ext.JSON.decode(msg);
            // Format the message text for line breaks.
            msg.message = this.nl2br(msg.message);
        } catch(e) {
            // Error message is plain text, e.g. error message from the
            // web server.
        }
        OMV.MessageBox.error(null, msg);
    },

    /**
     * Helper function to insert line breaks back into the error message
     * @param str The message to process for line breaks.
     * @param is_xhtml Boolean, whether to insert XHTML-compatible <br/>
     *                 tags or not (default is true).
     */
    nl2br: function(str, is_xhtml) {
        var breakTag = (is_xhtml || typeof is_xhtml === 'undefined') ? '<br />' : '<br>';
        return (str + '').replace(/([^>\r\n]?)(\r\n|\n\r|\r|\n)/g, '$1' + breakTag + '$2');
    }
});


/**
 * @class OMV.module.admin.storage.luks.container.KillSlot
 * @derived OMV.workspace.window.Form
 * @param uuid The UUID of the configuration object.
 * @param devicefile The device file, e.g. /dev/sda.
 */
Ext.define("OMV.module.admin.storage.luks.container.KillSlot", {
    extend: "OMV.workspace.window.Form",

    rpcService: "LuksMgmt",
    rpcSetMethod: "killContainerKeySlot",
    title: _("Erase key slot"),
    okButtonText: _("Erase"),
    autoLoadData: false,
    hideResetButton: true,
    width: 540,

    initComponent: function() {
        var me = this;
        me.callParent(arguments);
        me.on("show", function() {
                       // Set focus to field 'keyslot'.
                       var field = me.fp.findField("keyslot");
                       if (!Ext.isEmpty(field))
                               field.focus(false, 500);
               }, me);
    },

    getFormItems: function() {
        var me = this;
        return [{
            xtype: "textfield",
            name: "devicefile",
            fieldLabel: _("Device"),
            allowBlank: false,
            readOnly: true,
            value: me.params.devicefile,
            listeners: {
                scope: me,
                specialkey: me.submitOnEnter
            }
        },{
            xtype: "numberfield",
            name: "keyslot",
            fieldLabel: _("Key slot"),
            emptyText: _("Choose a slot to erase ..."),
            minValue: 0,
            maxValue: 7,
            allowDecimals: false,
            allowBlank: false,
            plugins: [{
                    ptype: "fieldinfo",
                    text: _("The key slot to erase (0-7). Use the 'Test key' or 'Detail' functions to decide which slot you want to destroy.")
            }],
            listeners: {
                scope: me,
                specialkey: me.submitOnEnter
            }
        }];
    },

    doSubmit: function() {
        var me = this;
        var basicForm = me.fp.getForm();
        if(!basicForm.isValid())
            return;
        OMV.MessageBox.show({
            title: _("Confirmation"),
            msg: _("Do you really want to erase this key slot? Ensure you have another key which unlocks the device."),
            buttons: Ext.Msg.YESNO,
            fn: function(answer) {
                if(answer === "no")
                    return;
                if(me.params.usedslots == 1)
                    OMV.MessageBox.show({
                        title: _("Erase key slot"),
                        msg: _("Are you really sure you want to erase this key slot? The device has only one active key slot; removing the last key renders the device permanently inaccessible."),
                        icon: Ext.Msg.WARNING,
                        buttonText: {
                            yes: _("No"),
                            no: _("Yes")
                        },
                        scope: me,
                        fn: function(answer) {
                            switch(answer) {
                            case "no": // Attention, switched buttons.
                                me.superclass.doSubmit.call(me);
                                break;
                            default:
                                return;
                                break;
                            }
                        }
                    });
                else
                    me.superclass.doSubmit.call(me);
            },
            scope: me,
            icon: Ext.Msg.QUESTION
        });
    },

    getRpcSetParams: function() {
        var me = this;
        var params = me.callParent(arguments);
        return Ext.apply(params, {
            uuid: me.params.uuid,
            devicefile: me.params.devicefile
        });
    },

    submitOnEnter: function(field, event) {
        var me = this;
        if (event.getKey() == event.ENTER) {
            me.superclass.onOkButton.call(me);
        }
    }
});


/**
 * @class OMV.module.admin.storage.luks.container.Detail
 * @derived OMV.workspace.window.TextArea
 */
Ext.define("OMV.module.admin.storage.luks.container.Detail", {
    extend: "OMV.workspace.window.TextArea",

    rpcService: "LuksMgmt",
    rpcGetMethod: "getContainerDetails",
    title: _("Encrypted device details"),
    width: 600,
    height: 500
});


/**
 * @class OMV.module.admin.storage.luks.container.RestoreHeader
 * @derived OMV.window.Upload
 * @param params An array with additional RPC method parameters. Required:
 *      \em devicefile The device to write the header to (selected item)
 * @param title The dialog title.
 * @param waitMsg The displayed waiting message.
 */
Ext.define("OMV.module.admin.storage.luks.container.RestoreHeader", {
    extend: "OMV.window.Window",
    requires: [
        "OMV.form.Panel",
    ],

    url: "upload.php",
    title: _("Upload header backup file"),
    waitMsg: _("Uploading header backup file ..."),
    width: 450,
    layout: "fit",
    modal: true,
    buttonAlign: "center",

    constructor: function() {
        var me = this;
        me.callParent(arguments);
        /**
         * @event success
         * Fires after the installation has been finished successful.
         * @param this The window object.
         * @param response The response from the form submit action.
         */
    },

    initComponent: function() {
        var me = this;
        Ext.apply(me, {
            buttons: [{
                text: _("OK"),
                handler: me.onOkButton,
                scope: me
            },{
                text: _("Cancel"),
                handler: me.onCancelButton,
                scope: me
            }],
            items: [ me.fp = Ext.create("OMV.form.Panel", {
                bodyPadding: "5 5 0",
                items: [{
                    // Dummy field to reinforce which device will be affected
                    xtype: "textfield",
                    name: "devicefile",
                    fieldLabel: _("Device"),
                    allowBlank: false,
                    readOnly: true,
                    value: me.params.devicefile,
                    submitValue: false  // Don't submit as upload.php will baulk
                },{
                    // Dummy field to reinforce which device will be affected,
                    // and help the user select the right backup file
                    xtype: "textfield",
                    name: "uuid",
                    fieldLabel: _("UUID"),
                    allowBlank: false,
                    readOnly: true,
                    value: me.params.uuid,
                    submitValue: false  // Don't submit as upload.php will baulk
                },{
                    xtype: "filefield",
                    name: "file",
                    fieldLabel: _("Header file"),
                    allowBlank: false
                },{
                    // Force overwriting the header when the UUIDs don't match
                    xtype: "checkbox",
                    name: "force",
                    fieldLabel: _("Force"),
                    checked: false,
                    boxLabel: _("Overwrite the header even if the UUID from the backup doesn't match the device."),
                    submitValue: false  // Don't submit as upload.php will baulk
                }]
            }) ]
        });
        me.callParent(arguments);
    },

    /**
     * Method that is called when the 'OK' button is pressed.
     */
    onOkButton: function() {
        var me = this;
        var basicForm = me.fp.getForm();
        if(!basicForm.isValid())
            return;
        OMV.MessageBox.show({
            title: _("Restore encrypted device header"),
            msg: _("Do you really want to write the header to the device?<br/>Replacing the header will destroy existing key slots."),
            icon: Ext.Msg.WARNING,
            buttonText: {
                yes: _("No"),
                no: _("Yes")
            },
            scope: me,
            fn: function(answer) {
                switch(answer) {
                case "no": // Attention, switched buttons.
                    me.doUpload();
                    break;
                default:
                    break;
                }
            }
        });
    },

    doUpload: function() {
        var me = this;
        var basicForm = me.fp.getForm();
        me.params.force = me.fp.findField("force").value;
        basicForm.submit({
            url: me.url,
            method: "POST",
            params: {
                service: "LuksMgmt",
                method: "restoreContainerHeader",
                params: !Ext.isEmpty(me.params) ? Ext.JSON.encode(
                  me.params).htmlspecialchars() : me.params
            },
            waitMsg: me.waitMsg,
            scope: me,
            success: function(form, action) {
                this.onUploadSuccess(form, action);
            },
            failure: function(form, action) {
                this.onUploadFailure(form, action);
            }
        });
    },

    /**
     * Method that is called when the 'Cancel' button is pressed.
     */
    onCancelButton: function() {
        this.close();
    },

    /**
     * Method that is called when the file upload was successful.
     * @param form The form that requested the action.
     * @param action The Action object which performed the operation.
     */
    onUploadSuccess: function(form, action) {
        var me = this;
        // !!! Attention !!! Fire event before window is closed,
        // otherwise the dialog's own listener is removed before the
        // event has been fired and the action has been executed.
        me.fireEvent("success", me, action.result);
        // Now close the dialog.
        me.close();
    },

    /**
     * Method that is called when the file upload has been failed.
     * @param form The form that requested the action.
     * @param action The Action object which performed the operation.
     */
    onUploadFailure: function(form, action) {
        var msg = action.response.responseText;
        try {
            // Try to decode JSON error messages.
            msg = Ext.JSON.decode(msg);
            // Format the message text for line breaks.
            msg.message = this.nl2br(msg.message);
        } catch(e) {
            // Error message is plain text, e.g. error message from the
            // web server.
        }
        OMV.MessageBox.error(null, msg);
    },

    /**
     * Helper function to insert line breaks back into the error message
     * @param str The message to process for line breaks.
     * @param is_xhtml Boolean, whether to insert XHTML-compatible <br/>
     *                 tags or not (default is true).
     */
    nl2br: function(str, is_xhtml) {
        var breakTag = (is_xhtml || typeof is_xhtml === 'undefined') ? '<br />' : '<br>';
        return (str + '').replace(/([^>\r\n]?)(\r\n|\n\r|\r|\n)/g, '$1' + breakTag + '$2');
    }
});


/**
 * @class OMV.module.admin.storage.luks.Containers
 * @derived OMV.workspace.grid.Panel
 */
Ext.define("OMV.module.admin.storage.luks.Containers", {
    extend: "OMV.workspace.grid.Panel",
    requires: [
        "OMV.data.Store",
        "OMV.data.Model",
        "OMV.data.proxy.Rpc"
    ],
    uses: [
        "OMV.module.admin.storage.luks.container.Create",
        "OMV.module.admin.storage.luks.container.Detail",
        "OMV.module.admin.storage.luks.container.SingleKey",
        "OMV.module.admin.storage.luks.container.DualKey",
        "OMV.module.admin.storage.luks.container.KillSlot",
        "OMV.module.admin.storage.luks.container.RestoreHeader"
    ],

    autoReload: true,
    rememberSelected: true,
    hideAddButton: true,
    hideEditButton: true,
    hidePagingToolbar: false,
    disableLoadMaskOnLoad: true,
    stateful: true,
    stateId: "5abd703b-5ec7-4248-9138-452db85d17d5",
    columns: [{
            xtype: "emptycolumn",
            text: _("Device"),
            sortable: true,
            dataIndex: "devicefile",
            stateId: "devicefile"
        },{
            xtype: "binaryunitcolumn",
            text: _("Size"),
            sortable: true,
            dataIndex: "size",
            stateId: "size"
        },{
            text: _("Unlocked"),
            sortable: true,
            dataIndex: "unlocked",
            stateId: "unlocked",
            width: 80,
            resizable: false,
            align: "center",
            renderer: function(value, metaData, record) {
                var iconCls;
                switch (record.get("unlockatboot")) {
                case 1:
                case true: // Device is in crypttab
                    iconCls = (true == value) ?
                        "grid-cell-booleaniconcolumn-led-blue" :
                        "grid-cell-booleaniconcolumn-led-red";
                    break;
                default: // Device is not in crypttab
                    iconCls = (true == value) ?
                        "grid-cell-booleaniconcolumn-led-blue" :
                        "grid-cell-booleaniconcolumn-led-gray";
                    break;
                }
                metaData.tdCls = Ext.baseCSSPrefix +
                    "grid-cell-booleaniconcolumn" + " " +
                    Ext.baseCSSPrefix + iconCls;
                return "";
            }
        },{
            text: _("Decrypted device"),
            sortable: true,
            dataIndex: "decrypteddevicefile",
            stateId: "decrypteddevicefile",
            renderer: function(value) {
                if (!value || 0 === value.length) {
                    value = _("n/a");
                }
                return value;
            }
        },{
            text: _("Referenced"),
            sortable: true,
            dataIndex: "_used",
            stateId: "_used",
            renderer: function(value, metaData, record) {
                if (!record.get("unlocked")) {
                    // Not unlocked so we don't know if the
                    // decrypted device is used or not
                    value = _("n/a");
                } else {
                    value = OMV.util.Format.boolean(value);
                }
                return value;
            }
        },{
            text: _("Key slots in use"),
            sortable: true,
            dataIndex: "usedslots",
            stateId: "usedslots",
            renderer: function(value) {
                return value + "/8";
            }
        }],

    initComponent: function() {
        var me = this;
        Ext.apply(me, {
            store: Ext.create("OMV.data.Store", {
                autoLoad: true,
                model: OMV.data.Model.createImplicit({
                    // Note, do not use 'devicefile' as idProperty, because
                    // it is not guaranteed that the devicefile is set. This
                    // is the case when a device is configured for mounting
                    // but does not exist (e.g. USB).
                    identifier: "uuid", // Populate 'id' field automatically.
                    idProperty: "id",
                    fields: [
                        { name: "id", type: "string", persist: false },
                        { name: "uuid", type: "string" },
                        { name: "devicefile", type: "string" },
                        { name: "size", type: "string" },
                        { name: "unlocked", type: "boolean" },
                        { name: "decrypteddevicefile", type: "string" },
                        { name: "_used", type: "boolean" }
                    ]
                }),
                proxy: {
                    type: "rpc",
                    rpcData: {
                        service: "LuksMgmt",
                        method: "getContainersList",
                        options: {
                            updatelastaccess: false
                        }
                    }
                },
                remoteSort: true,
                sorters: [{
                    direction: "ASC",
                    property: "devicefile"
                }]
            })
        });
        me.callParent(arguments);
    },

    getTopToolbarItems: function() {
        var me = this;
        var items = me.callParent(arguments);
        Ext.Array.insert(items, 1, [{
            id: me.getId() + "-create",
            xtype: "button",
            text: _("Create"),
            icon: "images/add.svg",
            iconCls: Ext.baseCSSPrefix + "btn-icon-16x16",
            handler: Ext.Function.bind(me.onCreateButton, me, [ me ]),
            scope: me,
            disabled: false
        },{
            id: me.getId() + "-unlock",
            xtype: "button",
            text: _("Unlock"),
            icon: "images/padlock-open.svg",
            iconCls: Ext.baseCSSPrefix + "btn-icon-16x16",
            handler: Ext.Function.bind(me.onUnlockButton, me, [ me ]),
            scope: me,
            disabled: true
        },{
            id: me.getId() + "-lock",
            xtype: "button",
            text: _("Lock"),
            icon: "images/padlock-closed.svg",
            iconCls: Ext.baseCSSPrefix + "btn-icon-16x16",
            handler: Ext.Function.bind(me.onLockButton, me, [ me ]),
            scope: me,
            disabled: true
        },{
            id: me.getId() + "-keys",
            xtype: "splitbutton",
            text: _("Keys"),
            icon: "images/key.svg",
            iconCls: Ext.baseCSSPrefix + "btn-icon-16x16",
            disabled: true,
            handler: function() {
                this.showMenu();
            },
            menu: Ext.create("Ext.menu.Menu", {
                items: [{
                            text: _("Add"),
                            value: "add",
                            icon: "images/add.svg",
                            iconCls: Ext.baseCSSPrefix + "btn-icon-16x16"
                        },{
                            text: _("Change"),
                            value: "change",
                            icon: "images/edit.svg",
                            iconCls: Ext.baseCSSPrefix + "btn-icon-16x16"
                        },{
                            text: _("Remove"),
                            value: "remove",
                            icon: "images/minus.svg",
                            iconCls: Ext.baseCSSPrefix + "btn-icon-16x16"
                        },{
                            text: _("Test"),
                            value: "test",
                            icon: "images/info.svg",
                            iconCls: Ext.baseCSSPrefix + "btn-icon-16x16"
                        },{
                            text: _("Erase slot"),
                            value: "kill",
                            icon: "images/delete.svg",
                            iconCls: Ext.baseCSSPrefix + "btn-icon-16x16"
                        }],
                listeners: {
                    scope: me,
                    click: function(menu, item, e, eOpts) {
                        this.onKeysButton(item.value);
                    }
                }
            })
        },{
            id: me.getId() + "-header",
            xtype: "splitbutton",
            text: _("Recovery"),
            icon: "images/aid.svg",
            iconCls: Ext.baseCSSPrefix + "btn-icon-16x16",
            disabled: true,
            handler: function() {
                this.showMenu();
            },
            menu: Ext.create("Ext.menu.Menu", {
                items: [{
                            text: _("Backup header"),
                            value: "backup",
                            icon: "images/download.svg",
                            iconCls: Ext.baseCSSPrefix + "btn-icon-16x16"
                        },{
                            text: _("Restore header"),
                            value: "restore",
                            icon: "images/upload.svg",
                            iconCls: Ext.baseCSSPrefix + "btn-icon-16x16"
                        }],
                listeners: {
                    scope: me,
          click: function(menu, item, e, eOpts) {
                        this.onHeaderButton(item.value);
          }
                }
            })
        },{
            id: me.getId() + "-detail",
            xtype: "button",
            text: _("Detail"),
            icon: "images/details.svg",
            iconCls: Ext.baseCSSPrefix + "btn-icon-16x16",
            handler: me.onDetailButton,
            scope: me,
            disabled: true
        }]);
        return items;
    },

    onSelectionChange: function(model, records) {
        var me = this;
        me.callParent(arguments);
        // Process additional buttons.
        var tbarBtnDisabled = {
            "delete": true,
            "unlock": true,
            "lock": true,
            "keys": true,
            "detail": true,
            "header": true
        };
        if (records.length <= 0) {
            tbarBtnDisabled["delete"] = true;
            tbarBtnDisabled["unlock"] = true;
            tbarBtnDisabled["lock"] = true;
            tbarBtnDisabled["keys"] = true;
            tbarBtnDisabled["detail"] = true;
            tbarBtnDisabled["header"] = true;
        } else if(records.length == 1) {
            var record = records[0];
            // Set default values.
            tbarBtnDisabled["delete"] = true;
            tbarBtnDisabled["unlock"] = true;
            tbarBtnDisabled["lock"] = true;
            tbarBtnDisabled["keys"] = false;
            tbarBtnDisabled["detail"] = false;
            tbarBtnDisabled["header"] = false;
            // Disable/enable the unlock/lock buttons depending on whether
            // the selected device is open.
            if (true === record.get("unlocked")) {
                tbarBtnDisabled["lock"] = false;
                tbarBtnDisabled["delete"] = true;
            } else {
                tbarBtnDisabled["unlock"] = false;
                tbarBtnDisabled["delete"] = false;
                // Disable buttons if the device does not
                // provide a UUID.
                if(Ext.isEmpty(record.get("uuid"))) {
                    tbarBtnDisabled["unlock"] = true;
                    tbarBtnDisabled["header"] = true;
                    tbarBtnDisabled["delete"] = true;
                }
            }
            // If the device is in use, then also disable the lock
            // button.
            if (true === record.get("_used"))
                tbarBtnDisabled["lock"] = true;
        } else {
            // Set default values.
            tbarBtnDisabled["delete"] = false;
            tbarBtnDisabled["unlock"] = true;
            tbarBtnDisabled["lock"] = true;
            tbarBtnDisabled["keys"] = true;
            tbarBtnDisabled["detail"] = true;
            tbarBtnDisabled["header"] = true;
        }
        // Disable 'Delete' button if a selected device is in use or unlocked
        for (var i = 0; i < records.length; i++) {
            if (true == records[i].get("_used")) {
                tbarBtnDisabled["delete"] = true;
            }
            if (true == records[i].get("unlocked")) {
                tbarBtnDisabled["delete"] = true;
            }
        }
        // Update the button controls.
        Ext.Object.each(tbarBtnDisabled, function(key, value) {
            this.setToolbarButtonDisabled(key, value);
        }, me);
    },

    onCreateButton: function() {
        var me = this;
        Ext.create("OMV.module.admin.storage.luks.container.Create", {
            listeners: {
                scope: me,
                submit: function() {
                    this.doReload();
                }
            }
        }).show();
    },

    onUnlockButton: function() {
        var me = this;
        var record = me.getSelected();
        Ext.create("OMV.module.admin.storage.luks.container.SingleKey", {
            title:      _("Unlock encrypted device"),
            submitMsg:      _("Unlocking ..."),
            okButtonText:   _("Unlock"),
            rpcSetMethod:  "openContainer",
            params: {
                uuid:       record.get("uuid"),
                devicefile: record.get("devicefile")
            },
            listeners: [{
                scope: me,
                submit: function() {
                    this.doReload();
                }
            }]
        }).show();
    },

    onLockButton: function() {
        var me = this;
        var record = me.getSelected();
        var df = record.get("devicefile");
        // Display waiting dialog
        OMV.MessageBox.wait(null, _("Locking device ..."));
        // Execute RPC.
        OMV.Rpc.request({
            scope: me,
            callback: function(df, success, response) {
                OMV.MessageBox.updateProgress(1);
                OMV.MessageBox.hide();
                if (success) {
                    this.doReload();
                } else {
                  OMV.MessageBox.error(null, response);
                }
            },
            relayErrors: true,
            rpcData: {
                service: "LuksMgmt",
                method: "closeContainer",
                params: {
                    devicefile: df
                }
            }
        });
    },

    onKeysButton: function(action) {
        var me = this;
        var record = me.getSelected();
        switch(action) {
            case "add":
                Ext.create("OMV.module.admin.storage.luks.container.DualKey", {
                    title:          _("Add key"),
                    okButtonText:   _("Add"),
                    rpcSetMethod:   "addContainerKey",
                    params: {
                        uuid:       record.get("uuid"),
                        devicefile: record.get("devicefile")
                    },
                    listeners: {
                        scope: me,
                        submit: function() {
                            this.doReload();
                        }
                    }
                }).show();
                break;
            case "change":
                Ext.create("OMV.module.admin.storage.luks.container.DualKey", {
                    title:          _("Change key"),
                    okButtonText:   _("Change"),
                    rpcSetMethod:   "changeContainerKey",
                    params: {
                        uuid:       record.get("uuid"),
                        devicefile: record.get("devicefile")
                    },
                    listeners: {
                        scope: me,
                        submit: function() {
                            this.doReload();
                        }
                    }
                }).show();
                break;
            case "remove":
                Ext.create("OMV.module.admin.storage.luks.container.SingleKey", {
                    title:          _("Remove key"),
                    okButtonText:   _("Remove"),
                    rpcSetMethod:   "removeContainerKey",
                    params: {
                        uuid:       record.get("uuid"),
                        devicefile: record.get("devicefile"),
                        usedslots:  record.get("usedslots")
                    },
                    listeners: [{
                        scope: me,
                        submit: function() {
                            this.doReload();
                        }
                    },{
                        scope: me,
                        askconfirmation: function(you) {
                            OMV.MessageBox.show({
                                title: _("Confirmation"),
                                msg: _("Do you really want to remove this key? Ensure you have another key which unlocks the device."),
                                buttons: Ext.Msg.YESNO,
                                fn: function(answer) {
                                    if(answer === "no")
                                        return;
                                    if(you.params.usedslots == 1)
                                        OMV.MessageBox.show({
                                            title: _("Remove key"),
                                            msg: _("Are you really sure you want to remove this key? The device has only one active key slot; removing the last key renders the device permanently inaccessible."),
                                            icon: Ext.Msg.WARNING,
                                            buttonText: {
                                                yes: _("No"),
                                                no: _("Yes")
                                            },
                                            scope: me,
                                            fn: function(answer) {
                                                switch(answer) {
                                                case "no": // Attention, switched buttons.
                                                    you.doSubmit();
                                                    break;
                                                default:
                                                    return;
                                                    break;
                                                }
                                            }
                                        });
                                    else
                                        you.doSubmit();
                                },
                                scope: me,
                                icon: Ext.Msg.QUESTION
                            });
                            return false; // pass control to the messagebox
                        }
                    }]
                }).show();
                break;
            case "test":
                Ext.create("OMV.module.admin.storage.luks.container.SingleKey", {
                    title:          _("Test key"),
                    submitMsg:      _("Unlocking ..."),
                    okButtonText:   _("Unlock"),
                    rpcSetMethod:   "testContainerKey",
                    params: {
                        uuid:       record.get("uuid"),
                        devicefile: record.get("devicefile")
                    },
                    listeners: [{
                        scope: me,
                        submit: function(wnd, response, keyslot) {
                            OMV.MessageBox.show({
                                title: _("Success"),
                                msg: _("Successfully unlocked key slot ") + keyslot,
                                buttons: Ext.Msg.OK,
                                scope: me,
                                icon: Ext.Msg.INFO
                            });
                            this.doReload();
                        }
                    }]
                }).show();
                break;
            case "kill":
                Ext.create("OMV.module.admin.storage.luks.container.KillSlot", {
                    params: {
                        uuid:       record.get("uuid"),
                        devicefile: record.get("devicefile"),
                        usedslots:  record.get("usedslots")
                    },
                    listeners: {
                        scope: me,
                        submit: function() {
                            this.doReload();
                        }
                    }
                }).show();
                break;
        }
    },

    onHeaderButton: function(action) {
        var me = this;
        var record = me.getSelected();
        var uuid = record.get("uuid");
        switch(action) {
            case "backup":
                OMV.Download.request("LuksMgmt",
                                     "backupContainerHeader",
                                     { devicefile: record.get("devicefile") }
                                    );
                break;
            case "restore":
                Ext.create("OMV.module.admin.storage.luks.container.RestoreHeader", {
                    params: {
                        devicefile: record.get("devicefile"),
                        uuid:       record.get("uuid")
                    },
                    listeners: {
                        scope: me,
                        success: function(wnd, response) {
                            this.doReload();
                        }
                    }
                }).show();
                break;
        }
    },

    onItemDblClick: function() {
        var me = this;
        me.onDetailButton(me);
    },

    onDetailButton: function() {
        var me = this;
        var record = me.getSelected();
        Ext.create("OMV.module.admin.storage.luks.container.Detail", {
            rpcGetParams: {
                devicefile: record.get("devicefile")
            }
        }).show();
    },

    startDeletion: function(records) {
        var me = this;
        if(records.length <= 0)
            return;
        OMV.MessageBox.show({
            title: _("Delete encrypted device"),
            msg: _("Do you really want to delete the encrypted device?<br/>The encryption key will be destroyed and all data will be lost."),
            icon: Ext.Msg.WARNING,
            buttonText: {
                yes: _("No"),
                no: _("Yes")
            },
            scope: me,
            fn: function(answer) {
                switch(answer) {
                case "no": // Attention, switched buttons.
                    me.superclass.startDeletion.apply(this, [ records ]);
                    break;
                default:
                    break;
                }
            }
        });
    },

    doDeletion: function(record) {
        var me = this;
        var df = record.get("devicefile");
        // Execute RPC.
        OMV.Rpc.request({
            scope: me,
            callback: me.onDeletion,
            rpcData: {
                service: "LuksMgmt",
                method: "deleteContainer",
                params: {
                    devicefile: df
                }
            }
        });
    }
});


OMV.WorkspaceManager.registerPanel({
    id: "containers",
    path: "/storage/luks",
    text: _("Encrypted Devices"),
    position: 10,
    className: "OMV.module.admin.storage.luks.Containers"
});
