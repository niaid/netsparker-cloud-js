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
exports.AwsConnectionInfoModelToJSON = exports.AwsConnectionInfoModelFromJSONTyped = exports.AwsConnectionInfoModelFromJSON = exports.instanceOfAwsConnectionInfoModel = void 0;
/**
 * Check if a given object implements the AwsConnectionInfoModel interface.
 */
function instanceOfAwsConnectionInfoModel(value) {
    if (!('region' in value))
        return false;
    if (!('accessKeyId' in value))
        return false;
    if (!('secretAccessKey' in value))
        return false;
    return true;
}
exports.instanceOfAwsConnectionInfoModel = instanceOfAwsConnectionInfoModel;
function AwsConnectionInfoModelFromJSON(json) {
    return AwsConnectionInfoModelFromJSONTyped(json, false);
}
exports.AwsConnectionInfoModelFromJSON = AwsConnectionInfoModelFromJSON;
function AwsConnectionInfoModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'region': json['Region'],
        'accessKeyId': json['AccessKeyId'],
        'secretAccessKey': json['SecretAccessKey'],
        'showUnreachableDiscoveredWebsites': json['ShowUnreachableDiscoveredWebsites'] == null ? undefined : json['ShowUnreachableDiscoveredWebsites'],
    };
}
exports.AwsConnectionInfoModelFromJSONTyped = AwsConnectionInfoModelFromJSONTyped;
function AwsConnectionInfoModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Region': value['region'],
        'AccessKeyId': value['accessKeyId'],
        'SecretAccessKey': value['secretAccessKey'],
        'ShowUnreachableDiscoveredWebsites': value['showUnreachableDiscoveredWebsites'],
    };
}
exports.AwsConnectionInfoModelToJSON = AwsConnectionInfoModelToJSON;
//# sourceMappingURL=AwsConnectionInfoModel.js.map