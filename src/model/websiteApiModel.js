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
exports.WebsiteApiModel = void 0;
/**
* Represents a model for carrying out website data.
*/
class WebsiteApiModel {
    static getAttributeTypeMap() {
        return WebsiteApiModel.attributeTypeMap;
    }
}
exports.WebsiteApiModel = WebsiteApiModel;
WebsiteApiModel.discriminator = undefined;
WebsiteApiModel.attributeTypeMap = [
    {
        "name": "id",
        "baseName": "Id",
        "type": "string"
    },
    {
        "name": "createdAt",
        "baseName": "CreatedAt",
        "type": "Date"
    },
    {
        "name": "updatedAt",
        "baseName": "UpdatedAt",
        "type": "Date"
    },
    {
        "name": "rootUrl",
        "baseName": "RootUrl",
        "type": "string"
    },
    {
        "name": "name",
        "baseName": "Name",
        "type": "string"
    },
    {
        "name": "description",
        "baseName": "Description",
        "type": "string"
    },
    {
        "name": "technicalContactEmail",
        "baseName": "TechnicalContactEmail",
        "type": "string"
    },
    {
        "name": "groups",
        "baseName": "Groups",
        "type": "Array<IdNamePair>"
    },
    {
        "name": "isVerified",
        "baseName": "IsVerified",
        "type": "boolean"
    },
    {
        "name": "licenseType",
        "baseName": "LicenseType",
        "type": "WebsiteApiModel.LicenseTypeEnum"
    },
    {
        "name": "agentMode",
        "baseName": "AgentMode",
        "type": "WebsiteApiModel.AgentModeEnum"
    }
];
(function (WebsiteApiModel) {
    let LicenseTypeEnum;
    (function (LicenseTypeEnum) {
        LicenseTypeEnum[LicenseTypeEnum["Subscription"] = 'Subscription'] = "Subscription";
        LicenseTypeEnum[LicenseTypeEnum["Credit"] = 'Credit'] = "Credit";
    })(LicenseTypeEnum = WebsiteApiModel.LicenseTypeEnum || (WebsiteApiModel.LicenseTypeEnum = {}));
    let AgentModeEnum;
    (function (AgentModeEnum) {
        AgentModeEnum[AgentModeEnum["Cloud"] = 'Cloud'] = "Cloud";
        AgentModeEnum[AgentModeEnum["Internal"] = 'Internal'] = "Internal";
    })(AgentModeEnum = WebsiteApiModel.AgentModeEnum || (WebsiteApiModel.AgentModeEnum = {}));
})(WebsiteApiModel = exports.WebsiteApiModel || (exports.WebsiteApiModel = {}));
//# sourceMappingURL=websiteApiModel.js.map