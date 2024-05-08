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
/**
 * Check if a given object implements the WebsiteGroupApiModel interface.
 */
function instanceOfWebsiteGroupApiModel(value) {
    if (!('id' in value))
        return false;
    if (!('name' in value))
        return false;
    return true;
}
exports.instanceOfWebsiteGroupApiModel = instanceOfWebsiteGroupApiModel;
function WebsiteGroupApiModelFromJSON(json) {
    return WebsiteGroupApiModelFromJSONTyped(json, false);
}
exports.WebsiteGroupApiModelFromJSON = WebsiteGroupApiModelFromJSON;
function WebsiteGroupApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'totalWebsites': json['TotalWebsites'] == null ? undefined : json['TotalWebsites'],
        'createdAt': json['CreatedAt'] == null ? undefined : (new Date(json['CreatedAt'])),
        'updatedAt': json['UpdatedAt'] == null ? undefined : (new Date(json['UpdatedAt'])),
        'id': json['Id'],
        'name': json['Name'],
        'description': json['Description'] == null ? undefined : json['Description'],
        'tags': json['Tags'] == null ? undefined : json['Tags'],
    };
}
exports.WebsiteGroupApiModelFromJSONTyped = WebsiteGroupApiModelFromJSONTyped;
function WebsiteGroupApiModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'TotalWebsites': value['totalWebsites'],
        'CreatedAt': value['createdAt'] == null ? undefined : ((value['createdAt']).toISOString()),
        'UpdatedAt': value['updatedAt'] == null ? undefined : ((value['updatedAt']).toISOString()),
        'Id': value['id'],
        'Name': value['name'],
        'Description': value['description'],
        'Tags': value['tags'],
    };
}
exports.WebsiteGroupApiModelToJSON = WebsiteGroupApiModelToJSON;
//# sourceMappingURL=WebsiteGroupApiModel.js.map