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
exports.NewWebsiteApiModelToJSON = exports.NewWebsiteApiModelFromJSONTyped = exports.NewWebsiteApiModelFromJSON = exports.instanceOfNewWebsiteApiModel = exports.NewWebsiteApiModelLicenseTypeEnum = exports.NewWebsiteApiModelAgentModeEnum = void 0;
const runtime_1 = require("../runtime");
/**
* @export
* @enum {string}
*/
var NewWebsiteApiModelAgentModeEnum;
(function (NewWebsiteApiModelAgentModeEnum) {
    NewWebsiteApiModelAgentModeEnum["Cloud"] = "Cloud";
    NewWebsiteApiModelAgentModeEnum["Internal"] = "Internal";
})(NewWebsiteApiModelAgentModeEnum = exports.NewWebsiteApiModelAgentModeEnum || (exports.NewWebsiteApiModelAgentModeEnum = {}));
/**
* @export
* @enum {string}
*/
var NewWebsiteApiModelLicenseTypeEnum;
(function (NewWebsiteApiModelLicenseTypeEnum) {
    NewWebsiteApiModelLicenseTypeEnum["Subscription"] = "Subscription";
    NewWebsiteApiModelLicenseTypeEnum["Credit"] = "Credit";
})(NewWebsiteApiModelLicenseTypeEnum = exports.NewWebsiteApiModelLicenseTypeEnum || (exports.NewWebsiteApiModelLicenseTypeEnum = {}));
/**
 * Check if a given object implements the NewWebsiteApiModel interface.
 */
function instanceOfNewWebsiteApiModel(value) {
    let isInstance = true;
    isInstance = isInstance && "rootUrl" in value;
    isInstance = isInstance && "licenseType" in value;
    isInstance = isInstance && "name" in value;
    return isInstance;
}
exports.instanceOfNewWebsiteApiModel = instanceOfNewWebsiteApiModel;
function NewWebsiteApiModelFromJSON(json) {
    return NewWebsiteApiModelFromJSONTyped(json, false);
}
exports.NewWebsiteApiModelFromJSON = NewWebsiteApiModelFromJSON;
function NewWebsiteApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'agentMode': !(0, runtime_1.exists)(json, 'AgentMode') ? undefined : json['AgentMode'],
        'rootUrl': json['RootUrl'],
        'groups': !(0, runtime_1.exists)(json, 'Groups') ? undefined : json['Groups'],
        'licenseType': json['LicenseType'],
        'name': json['Name'],
        'description': !(0, runtime_1.exists)(json, 'Description') ? undefined : json['Description'],
        'technicalContactEmail': !(0, runtime_1.exists)(json, 'TechnicalContactEmail') ? undefined : json['TechnicalContactEmail'],
        'tags': !(0, runtime_1.exists)(json, 'Tags') ? undefined : json['Tags'],
    };
}
exports.NewWebsiteApiModelFromJSONTyped = NewWebsiteApiModelFromJSONTyped;
function NewWebsiteApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'AgentMode': value.agentMode,
        'RootUrl': value.rootUrl,
        'Groups': value.groups,
        'LicenseType': value.licenseType,
        'Name': value.name,
        'Description': value.description,
        'TechnicalContactEmail': value.technicalContactEmail,
        'Tags': value.tags,
    };
}
exports.NewWebsiteApiModelToJSON = NewWebsiteApiModelToJSON;
//# sourceMappingURL=NewWebsiteApiModel.js.map