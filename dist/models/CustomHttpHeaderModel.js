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
exports.CustomHttpHeaderModelToJSON = exports.CustomHttpHeaderModelFromJSONTyped = exports.CustomHttpHeaderModelFromJSON = exports.instanceOfCustomHttpHeaderModel = void 0;
/**
 * Check if a given object implements the CustomHttpHeaderModel interface.
 */
function instanceOfCustomHttpHeaderModel(value) {
    if (!('name' in value))
        return false;
    return true;
}
exports.instanceOfCustomHttpHeaderModel = instanceOfCustomHttpHeaderModel;
function CustomHttpHeaderModelFromJSON(json) {
    return CustomHttpHeaderModelFromJSONTyped(json, false);
}
exports.CustomHttpHeaderModelFromJSON = CustomHttpHeaderModelFromJSON;
function CustomHttpHeaderModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'name': json['Name'],
        'value': json['Value'] == null ? undefined : json['Value'],
        'originalName': json['OriginalName'] == null ? undefined : json['OriginalName'],
        'isReplacedCredentials': json['IsReplacedCredentials'] == null ? undefined : json['IsReplacedCredentials'],
    };
}
exports.CustomHttpHeaderModelFromJSONTyped = CustomHttpHeaderModelFromJSONTyped;
function CustomHttpHeaderModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Name': value['name'],
        'Value': value['value'],
        'OriginalName': value['originalName'],
        'IsReplacedCredentials': value['isReplacedCredentials'],
    };
}
exports.CustomHttpHeaderModelToJSON = CustomHttpHeaderModelToJSON;
//# sourceMappingURL=CustomHttpHeaderModel.js.map