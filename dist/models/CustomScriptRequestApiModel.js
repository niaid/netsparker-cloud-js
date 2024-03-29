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
exports.CustomScriptRequestApiModelToJSON = exports.CustomScriptRequestApiModelFromJSONTyped = exports.CustomScriptRequestApiModelFromJSON = exports.instanceOfCustomScriptRequestApiModel = exports.CustomScriptRequestApiModelTypeEnum = void 0;
const runtime_1 = require("../runtime");
/**
 * @export
 */
exports.CustomScriptRequestApiModelTypeEnum = {
    Active: 'Active',
    Passive: 'Passive',
    PerDirectory: 'PerDirectory',
    Singular: 'Singular'
};
/**
 * Check if a given object implements the CustomScriptRequestApiModel interface.
 */
function instanceOfCustomScriptRequestApiModel(value) {
    let isInstance = true;
    isInstance = isInstance && "name" in value;
    isInstance = isInstance && "content" in value;
    return isInstance;
}
exports.instanceOfCustomScriptRequestApiModel = instanceOfCustomScriptRequestApiModel;
function CustomScriptRequestApiModelFromJSON(json) {
    return CustomScriptRequestApiModelFromJSONTyped(json, false);
}
exports.CustomScriptRequestApiModelFromJSON = CustomScriptRequestApiModelFromJSON;
function CustomScriptRequestApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'type': !(0, runtime_1.exists)(json, 'Type') ? undefined : json['Type'],
        'name': json['Name'],
        'content': json['Content'],
    };
}
exports.CustomScriptRequestApiModelFromJSONTyped = CustomScriptRequestApiModelFromJSONTyped;
function CustomScriptRequestApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Type': value.type,
        'Name': value.name,
        'Content': value.content,
    };
}
exports.CustomScriptRequestApiModelToJSON = CustomScriptRequestApiModelToJSON;
//# sourceMappingURL=CustomScriptRequestApiModel.js.map