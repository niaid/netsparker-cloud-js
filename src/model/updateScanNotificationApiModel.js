"use strict";
/**
 * Netsparker Enterprise API
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: v1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
Object.defineProperty(exports, "__esModule", { value: true });
/**
* Represents a model for carrying out an update scan notification data
*/
class UpdateScanNotificationApiModel {
    static getAttributeTypeMap() {
        return UpdateScanNotificationApiModel.attributeTypeMap;
    }
}
UpdateScanNotificationApiModel.discriminator = undefined;
UpdateScanNotificationApiModel.attributeTypeMap = [
    {
        "name": "id",
        "baseName": "Id",
        "type": "string"
    },
    {
        "name": "recipients",
        "baseName": "Recipients",
        "type": "NewScanNotificationRecipientApiModel"
    },
    {
        "name": "websiteGroupName",
        "baseName": "WebsiteGroupName",
        "type": "string"
    },
    {
        "name": "websiteRootUrl",
        "baseName": "WebsiteRootUrl",
        "type": "string"
    },
    {
        "name": "certainty",
        "baseName": "Certainty",
        "type": "number"
    },
    {
        "name": "disabled",
        "baseName": "Disabled",
        "type": "boolean"
    },
    {
        "name": "scanTaskGroupId",
        "baseName": "ScanTaskGroupId",
        "type": "string"
    },
    {
        "name": "event",
        "baseName": "Event",
        "type": "UpdateScanNotificationApiModel.EventEnum"
    },
    {
        "name": "isConfirmed",
        "baseName": "IsConfirmed",
        "type": "boolean"
    },
    {
        "name": "severity",
        "baseName": "Severity",
        "type": "UpdateScanNotificationApiModel.SeverityEnum"
    },
    {
        "name": "state",
        "baseName": "State",
        "type": "UpdateScanNotificationApiModel.StateEnum"
    },
    {
        "name": "name",
        "baseName": "Name",
        "type": "string"
    },
    {
        "name": "scope",
        "baseName": "Scope",
        "type": "UpdateScanNotificationApiModel.ScopeEnum"
    }
];
exports.UpdateScanNotificationApiModel = UpdateScanNotificationApiModel;
(function (UpdateScanNotificationApiModel) {
    let EventEnum;
    (function (EventEnum) {
        EventEnum[EventEnum["NewScan"] = 'NewScan'] = "NewScan";
        EventEnum[EventEnum["ScanCompleted"] = 'ScanCompleted'] = "ScanCompleted";
        EventEnum[EventEnum["ScanCancelled"] = 'ScanCancelled'] = "ScanCancelled";
        EventEnum[EventEnum["ScanFailed"] = 'ScanFailed'] = "ScanFailed";
        EventEnum[EventEnum["ScheduledScanLaunchFailed"] = 'ScheduledScanLaunchFailed'] = "ScheduledScanLaunchFailed";
        EventEnum[EventEnum["OutOfDateTechnology"] = 'OutOfDateTechnology'] = "OutOfDateTechnology";
    })(EventEnum = UpdateScanNotificationApiModel.EventEnum || (UpdateScanNotificationApiModel.EventEnum = {}));
    let SeverityEnum;
    (function (SeverityEnum) {
        SeverityEnum[SeverityEnum["BestPractice"] = 'BestPractice'] = "BestPractice";
        SeverityEnum[SeverityEnum["Information"] = 'Information'] = "Information";
        SeverityEnum[SeverityEnum["Low"] = 'Low'] = "Low";
        SeverityEnum[SeverityEnum["Medium"] = 'Medium'] = "Medium";
        SeverityEnum[SeverityEnum["High"] = 'High'] = "High";
        SeverityEnum[SeverityEnum["Critical"] = 'Critical'] = "Critical";
    })(SeverityEnum = UpdateScanNotificationApiModel.SeverityEnum || (UpdateScanNotificationApiModel.SeverityEnum = {}));
    let StateEnum;
    (function (StateEnum) {
        StateEnum[StateEnum["NotFound"] = 'NotFound'] = "NotFound";
        StateEnum[StateEnum["Fixed"] = 'Fixed'] = "Fixed";
        StateEnum[StateEnum["NotFixed"] = 'NotFixed'] = "NotFixed";
        StateEnum[StateEnum["New"] = 'New'] = "New";
        StateEnum[StateEnum["Revived"] = 'Revived'] = "Revived";
    })(StateEnum = UpdateScanNotificationApiModel.StateEnum || (UpdateScanNotificationApiModel.StateEnum = {}));
    let ScopeEnum;
    (function (ScopeEnum) {
        ScopeEnum[ScopeEnum["AnyWebsite"] = 'AnyWebsite'] = "AnyWebsite";
        ScopeEnum[ScopeEnum["WebsiteGroup"] = 'WebsiteGroup'] = "WebsiteGroup";
        ScopeEnum[ScopeEnum["Website"] = 'Website'] = "Website";
    })(ScopeEnum = UpdateScanNotificationApiModel.ScopeEnum || (UpdateScanNotificationApiModel.ScopeEnum = {}));
})(UpdateScanNotificationApiModel = exports.UpdateScanNotificationApiModel || (exports.UpdateScanNotificationApiModel = {}));
//# sourceMappingURL=updateScanNotificationApiModel.js.map