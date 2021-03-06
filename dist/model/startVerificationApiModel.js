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
exports.StartVerificationApiModel = void 0;
/**
* Represents a model to start verification.
*/
class StartVerificationApiModel {
    static getAttributeTypeMap() {
        return StartVerificationApiModel.attributeTypeMap;
    }
}
exports.StartVerificationApiModel = StartVerificationApiModel;
StartVerificationApiModel.discriminator = undefined;
StartVerificationApiModel.attributeTypeMap = [
    {
        "name": "verificationMethod",
        "baseName": "VerificationMethod",
        "type": "StartVerificationApiModel.VerificationMethodEnum"
    },
    {
        "name": "websiteUrl",
        "baseName": "WebsiteUrl",
        "type": "string"
    }
];
(function (StartVerificationApiModel) {
    let VerificationMethodEnum;
    (function (VerificationMethodEnum) {
        VerificationMethodEnum[VerificationMethodEnum["File"] = 'File'] = "File";
        VerificationMethodEnum[VerificationMethodEnum["Tag"] = 'Tag'] = "Tag";
        VerificationMethodEnum[VerificationMethodEnum["Dns"] = 'Dns'] = "Dns";
        VerificationMethodEnum[VerificationMethodEnum["Email"] = 'Email'] = "Email";
    })(VerificationMethodEnum = StartVerificationApiModel.VerificationMethodEnum || (StartVerificationApiModel.VerificationMethodEnum = {}));
})(StartVerificationApiModel = exports.StartVerificationApiModel || (exports.StartVerificationApiModel = {}));
//# sourceMappingURL=startVerificationApiModel.js.map