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
exports.NewGroupScanApiModel = void 0;
/**
* Contains properties that required to start group scan.
*/
class NewGroupScanApiModel {
    static getAttributeTypeMap() {
        return NewGroupScanApiModel.attributeTypeMap;
    }
}
exports.NewGroupScanApiModel = NewGroupScanApiModel;
NewGroupScanApiModel.discriminator = undefined;
NewGroupScanApiModel.attributeTypeMap = [
    {
        "name": "policyId",
        "baseName": "PolicyId",
        "type": "string"
    },
    {
        "name": "reportPolicyId",
        "baseName": "ReportPolicyId",
        "type": "string"
    },
    {
        "name": "authenticationProfileOption",
        "baseName": "AuthenticationProfileOption",
        "type": "NewGroupScanApiModel.AuthenticationProfileOptionEnum"
    },
    {
        "name": "authenticationProfileId",
        "baseName": "AuthenticationProfileId",
        "type": "string"
    },
    {
        "name": "timeWindow",
        "baseName": "TimeWindow",
        "type": "ScanTimeWindowModel"
    },
    {
        "name": "websiteGroupName",
        "baseName": "WebsiteGroupName",
        "type": "string"
    }
];
(function (NewGroupScanApiModel) {
    let AuthenticationProfileOptionEnum;
    (function (AuthenticationProfileOptionEnum) {
        AuthenticationProfileOptionEnum[AuthenticationProfileOptionEnum["DontUse"] = 'DontUse'] = "DontUse";
        AuthenticationProfileOptionEnum[AuthenticationProfileOptionEnum["UseMatchedProfile"] = 'UseMatchedProfile'] = "UseMatchedProfile";
        AuthenticationProfileOptionEnum[AuthenticationProfileOptionEnum["SelectedProfile"] = 'SelectedProfile'] = "SelectedProfile";
    })(AuthenticationProfileOptionEnum = NewGroupScanApiModel.AuthenticationProfileOptionEnum || (NewGroupScanApiModel.AuthenticationProfileOptionEnum = {}));
})(NewGroupScanApiModel = exports.NewGroupScanApiModel || (exports.NewGroupScanApiModel = {}));
//# sourceMappingURL=newGroupScanApiModel.js.map