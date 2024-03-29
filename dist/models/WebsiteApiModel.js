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
exports.WebsiteApiModelToJSON = exports.WebsiteApiModelFromJSONTyped = exports.WebsiteApiModelFromJSON = exports.instanceOfWebsiteApiModel = exports.WebsiteApiModelAgentModeEnum = exports.WebsiteApiModelLicenseTypeEnum = void 0;
const runtime_1 = require("../runtime");
const IdNamePair_1 = require("./IdNamePair");
/**
 * @export
 */
exports.WebsiteApiModelLicenseTypeEnum = {
    Subscription: 'Subscription',
    Credit: 'Credit'
};
/**
 * @export
 */
exports.WebsiteApiModelAgentModeEnum = {
    Cloud: 'Cloud',
    Internal: 'Internal'
};
/**
 * Check if a given object implements the WebsiteApiModel interface.
 */
function instanceOfWebsiteApiModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfWebsiteApiModel = instanceOfWebsiteApiModel;
function WebsiteApiModelFromJSON(json) {
    return WebsiteApiModelFromJSONTyped(json, false);
}
exports.WebsiteApiModelFromJSON = WebsiteApiModelFromJSON;
function WebsiteApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'id': !(0, runtime_1.exists)(json, 'Id') ? undefined : json['Id'],
        'createdAt': !(0, runtime_1.exists)(json, 'CreatedAt') ? undefined : (new Date(json['CreatedAt'])),
        'updatedAt': !(0, runtime_1.exists)(json, 'UpdatedAt') ? undefined : (new Date(json['UpdatedAt'])),
        'rootUrl': !(0, runtime_1.exists)(json, 'RootUrl') ? undefined : json['RootUrl'],
        'name': !(0, runtime_1.exists)(json, 'Name') ? undefined : json['Name'],
        'description': !(0, runtime_1.exists)(json, 'Description') ? undefined : json['Description'],
        'technicalContactEmail': !(0, runtime_1.exists)(json, 'TechnicalContactEmail') ? undefined : json['TechnicalContactEmail'],
        'groups': !(0, runtime_1.exists)(json, 'Groups') ? undefined : (json['Groups'].map(IdNamePair_1.IdNamePairFromJSON)),
        'isVerified': !(0, runtime_1.exists)(json, 'IsVerified') ? undefined : json['IsVerified'],
        'licenseType': !(0, runtime_1.exists)(json, 'LicenseType') ? undefined : json['LicenseType'],
        'agentMode': !(0, runtime_1.exists)(json, 'AgentMode') ? undefined : json['AgentMode'],
        'tags': !(0, runtime_1.exists)(json, 'Tags') ? undefined : json['Tags'],
    };
}
exports.WebsiteApiModelFromJSONTyped = WebsiteApiModelFromJSONTyped;
function WebsiteApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Id': value.id,
        'CreatedAt': value.createdAt === undefined ? undefined : (value.createdAt.toISOString()),
        'UpdatedAt': value.updatedAt === undefined ? undefined : (value.updatedAt.toISOString()),
        'RootUrl': value.rootUrl,
        'Name': value.name,
        'Description': value.description,
        'TechnicalContactEmail': value.technicalContactEmail,
        'Groups': value.groups === undefined ? undefined : (value.groups.map(IdNamePair_1.IdNamePairToJSON)),
        'IsVerified': value.isVerified,
        'LicenseType': value.licenseType,
        'AgentMode': value.agentMode,
        'Tags': value.tags,
    };
}
exports.WebsiteApiModelToJSON = WebsiteApiModelToJSON;
//# sourceMappingURL=WebsiteApiModel.js.map