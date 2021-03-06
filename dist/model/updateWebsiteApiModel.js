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
exports.UpdateWebsiteApiModel = void 0;
/**
* Represents a model for creating a website data.
*/
class UpdateWebsiteApiModel {
    static getAttributeTypeMap() {
        return UpdateWebsiteApiModel.attributeTypeMap;
    }
}
exports.UpdateWebsiteApiModel = UpdateWebsiteApiModel;
UpdateWebsiteApiModel.discriminator = undefined;
UpdateWebsiteApiModel.attributeTypeMap = [
    {
        "name": "defaultProtocol",
        "baseName": "DefaultProtocol",
        "type": "UpdateWebsiteApiModel.DefaultProtocolEnum"
    },
    {
        "name": "agentMode",
        "baseName": "AgentMode",
        "type": "UpdateWebsiteApiModel.AgentModeEnum"
    },
    {
        "name": "rootUrl",
        "baseName": "RootUrl",
        "type": "string"
    },
    {
        "name": "groups",
        "baseName": "Groups",
        "type": "Array<string>"
    },
    {
        "name": "licenseType",
        "baseName": "LicenseType",
        "type": "UpdateWebsiteApiModel.LicenseTypeEnum"
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
    }
];
(function (UpdateWebsiteApiModel) {
    let DefaultProtocolEnum;
    (function (DefaultProtocolEnum) {
        DefaultProtocolEnum[DefaultProtocolEnum["Http"] = 'Http'] = "Http";
        DefaultProtocolEnum[DefaultProtocolEnum["Https"] = 'Https'] = "Https";
    })(DefaultProtocolEnum = UpdateWebsiteApiModel.DefaultProtocolEnum || (UpdateWebsiteApiModel.DefaultProtocolEnum = {}));
    let AgentModeEnum;
    (function (AgentModeEnum) {
        AgentModeEnum[AgentModeEnum["Cloud"] = 'Cloud'] = "Cloud";
        AgentModeEnum[AgentModeEnum["Internal"] = 'Internal'] = "Internal";
    })(AgentModeEnum = UpdateWebsiteApiModel.AgentModeEnum || (UpdateWebsiteApiModel.AgentModeEnum = {}));
    let LicenseTypeEnum;
    (function (LicenseTypeEnum) {
        LicenseTypeEnum[LicenseTypeEnum["Subscription"] = 'Subscription'] = "Subscription";
        LicenseTypeEnum[LicenseTypeEnum["Credit"] = 'Credit'] = "Credit";
    })(LicenseTypeEnum = UpdateWebsiteApiModel.LicenseTypeEnum || (UpdateWebsiteApiModel.LicenseTypeEnum = {}));
})(UpdateWebsiteApiModel = exports.UpdateWebsiteApiModel || (exports.UpdateWebsiteApiModel = {}));
//# sourceMappingURL=updateWebsiteApiModel.js.map