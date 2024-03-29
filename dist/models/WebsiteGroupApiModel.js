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
exports.WebsiteGroupApiModelToJSON = exports.WebsiteGroupApiModelFromJSONTyped = exports.WebsiteGroupApiModelFromJSON = exports.instanceOfWebsiteGroupApiModel = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the WebsiteGroupApiModel interface.
 */
function instanceOfWebsiteGroupApiModel(value) {
    let isInstance = true;
    isInstance = isInstance && "id" in value;
    isInstance = isInstance && "name" in value;
    return isInstance;
}
exports.instanceOfWebsiteGroupApiModel = instanceOfWebsiteGroupApiModel;
function WebsiteGroupApiModelFromJSON(json) {
    return WebsiteGroupApiModelFromJSONTyped(json, false);
}
exports.WebsiteGroupApiModelFromJSON = WebsiteGroupApiModelFromJSON;
function WebsiteGroupApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'totalWebsites': !(0, runtime_1.exists)(json, 'TotalWebsites') ? undefined : json['TotalWebsites'],
        'createdAt': !(0, runtime_1.exists)(json, 'CreatedAt') ? undefined : (new Date(json['CreatedAt'])),
        'updatedAt': !(0, runtime_1.exists)(json, 'UpdatedAt') ? undefined : (new Date(json['UpdatedAt'])),
        'id': json['Id'],
        'name': json['Name'],
        'description': !(0, runtime_1.exists)(json, 'Description') ? undefined : json['Description'],
        'tags': !(0, runtime_1.exists)(json, 'Tags') ? undefined : json['Tags'],
    };
}
exports.WebsiteGroupApiModelFromJSONTyped = WebsiteGroupApiModelFromJSONTyped;
function WebsiteGroupApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'TotalWebsites': value.totalWebsites,
        'CreatedAt': value.createdAt === undefined ? undefined : (value.createdAt.toISOString()),
        'UpdatedAt': value.updatedAt === undefined ? undefined : (value.updatedAt.toISOString()),
        'Id': value.id,
        'Name': value.name,
        'Description': value.description,
        'Tags': value.tags,
    };
}
exports.WebsiteGroupApiModelToJSON = WebsiteGroupApiModelToJSON;
//# sourceMappingURL=WebsiteGroupApiModel.js.map