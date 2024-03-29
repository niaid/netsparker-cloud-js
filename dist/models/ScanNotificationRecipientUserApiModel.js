"use strict";
/* tslint:disable */
/* eslint-disable */
/**
 * Invicti Enterprise API
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
exports.ScanNotificationRecipientUserApiModelToJSON = exports.ScanNotificationRecipientUserApiModelFromJSONTyped = exports.ScanNotificationRecipientUserApiModelFromJSON = exports.instanceOfScanNotificationRecipientUserApiModel = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the ScanNotificationRecipientUserApiModel interface.
 */
function instanceOfScanNotificationRecipientUserApiModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfScanNotificationRecipientUserApiModel = instanceOfScanNotificationRecipientUserApiModel;
function ScanNotificationRecipientUserApiModelFromJSON(json) {
    return ScanNotificationRecipientUserApiModelFromJSONTyped(json, false);
}
exports.ScanNotificationRecipientUserApiModelFromJSON = ScanNotificationRecipientUserApiModelFromJSON;
function ScanNotificationRecipientUserApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'email': !(0, runtime_1.exists)(json, 'Email') ? undefined : json['Email'],
        'name': !(0, runtime_1.exists)(json, 'Name') ? undefined : json['Name'],
        'phoneNumber': !(0, runtime_1.exists)(json, 'PhoneNumber') ? undefined : json['PhoneNumber'],
    };
}
exports.ScanNotificationRecipientUserApiModelFromJSONTyped = ScanNotificationRecipientUserApiModelFromJSONTyped;
function ScanNotificationRecipientUserApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Email': value.email,
        'Name': value.name,
        'PhoneNumber': value.phoneNumber,
    };
}
exports.ScanNotificationRecipientUserApiModelToJSON = ScanNotificationRecipientUserApiModelToJSON;
//# sourceMappingURL=ScanNotificationRecipientUserApiModel.js.map