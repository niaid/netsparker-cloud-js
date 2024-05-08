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
exports.CustomFieldModelToJSON = exports.CustomFieldModelFromJSONTyped = exports.CustomFieldModelFromJSON = exports.instanceOfCustomFieldModel = void 0;
/**
 * Check if a given object implements the CustomFieldModel interface.
 */
function instanceOfCustomFieldModel(value) {
    return true;
}
exports.instanceOfCustomFieldModel = instanceOfCustomFieldModel;
function CustomFieldModelFromJSON(json) {
    return CustomFieldModelFromJSONTyped(json, false);
}
exports.CustomFieldModelFromJSON = CustomFieldModelFromJSON;
function CustomFieldModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'name': json['Name'] == null ? undefined : json['Name'],
        'values': json['Values'] == null ? undefined : json['Values'],
    };
}
exports.CustomFieldModelFromJSONTyped = CustomFieldModelFromJSONTyped;
function CustomFieldModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Name': value['name'],
        'Values': value['values'],
    };
}
exports.CustomFieldModelToJSON = CustomFieldModelToJSON;
//# sourceMappingURL=CustomFieldModel.js.map