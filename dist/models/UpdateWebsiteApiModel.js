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
exports.UpdateWebsiteApiModelToJSON = exports.UpdateWebsiteApiModelFromJSONTyped = exports.UpdateWebsiteApiModelFromJSON = exports.instanceOfUpdateWebsiteApiModel = exports.UpdateWebsiteApiModelLicenseTypeEnum = exports.UpdateWebsiteApiModelAgentModeEnum = exports.UpdateWebsiteApiModelDefaultProtocolEnum = void 0;
const runtime_1 = require("../runtime");
/**
 * @export
 */
exports.UpdateWebsiteApiModelDefaultProtocolEnum = {
    Http: 'Http',
    Https: 'Https'
};
/**
 * @export
 */
exports.UpdateWebsiteApiModelAgentModeEnum = {
    Cloud: 'Cloud',
    Internal: 'Internal'
};
/**
 * @export
 */
exports.UpdateWebsiteApiModelLicenseTypeEnum = {
    Subscription: 'Subscription',
    Credit: 'Credit'
};
/**
 * Check if a given object implements the UpdateWebsiteApiModel interface.
 */
function instanceOfUpdateWebsiteApiModel(value) {
    let isInstance = true;
    isInstance = isInstance && "rootUrl" in value;
    isInstance = isInstance && "licenseType" in value;
    isInstance = isInstance && "name" in value;
    return isInstance;
}
exports.instanceOfUpdateWebsiteApiModel = instanceOfUpdateWebsiteApiModel;
function UpdateWebsiteApiModelFromJSON(json) {
    return UpdateWebsiteApiModelFromJSONTyped(json, false);
}
exports.UpdateWebsiteApiModelFromJSON = UpdateWebsiteApiModelFromJSON;
function UpdateWebsiteApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'defaultProtocol': !(0, runtime_1.exists)(json, 'DefaultProtocol') ? undefined : json['DefaultProtocol'],
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
exports.UpdateWebsiteApiModelFromJSONTyped = UpdateWebsiteApiModelFromJSONTyped;
function UpdateWebsiteApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'DefaultProtocol': value.defaultProtocol,
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
exports.UpdateWebsiteApiModelToJSON = UpdateWebsiteApiModelToJSON;
//# sourceMappingURL=UpdateWebsiteApiModel.js.map