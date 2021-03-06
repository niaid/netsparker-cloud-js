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
exports.ScanNotificationRecipientUserApiModel = void 0;
/**
* Represents a model for carrying out a scan notification recipient user data
*/
class ScanNotificationRecipientUserApiModel {
    static getAttributeTypeMap() {
        return ScanNotificationRecipientUserApiModel.attributeTypeMap;
    }
}
exports.ScanNotificationRecipientUserApiModel = ScanNotificationRecipientUserApiModel;
ScanNotificationRecipientUserApiModel.discriminator = undefined;
ScanNotificationRecipientUserApiModel.attributeTypeMap = [
    {
        "name": "email",
        "baseName": "Email",
        "type": "string"
    },
    {
        "name": "name",
        "baseName": "Name",
        "type": "string"
    },
    {
        "name": "phoneNumber",
        "baseName": "PhoneNumber",
        "type": "string"
    }
];
//# sourceMappingURL=scanNotificationRecipientUserApiModel.js.map