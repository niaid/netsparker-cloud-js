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
exports.SendVerificationEmailModel = void 0;
/**
* Represents a verification result model.
*/
class SendVerificationEmailModel {
    static getAttributeTypeMap() {
        return SendVerificationEmailModel.attributeTypeMap;
    }
}
exports.SendVerificationEmailModel = SendVerificationEmailModel;
SendVerificationEmailModel.discriminator = undefined;
SendVerificationEmailModel.attributeTypeMap = [
    {
        "name": "isMailSent",
        "baseName": "IsMailSent",
        "type": "boolean"
    },
    {
        "name": "verificationMessage",
        "baseName": "VerificationMessage",
        "type": "string"
    }
];
//# sourceMappingURL=sendVerificationEmailModel.js.map