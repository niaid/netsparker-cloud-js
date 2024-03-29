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
exports.SharkModelToJSON = exports.SharkModelFromJSONTyped = exports.SharkModelFromJSON = exports.instanceOfSharkModel = exports.SharkModelSharkPlatformTypeEnum = void 0;
const runtime_1 = require("../runtime");
/**
 * @export
 */
exports.SharkModelSharkPlatformTypeEnum = {
    AspNet: 'AspNet',
    Php: 'Php',
    Java: 'Java',
    NodeJs: 'NodeJs'
};
/**
 * Check if a given object implements the SharkModel interface.
 */
function instanceOfSharkModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfSharkModel = instanceOfSharkModel;
function SharkModelFromJSON(json) {
    return SharkModelFromJSONTyped(json, false);
}
exports.SharkModelFromJSON = SharkModelFromJSON;
function SharkModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'isSharkEnabled': !(0, runtime_1.exists)(json, 'IsSharkEnabled') ? undefined : json['IsSharkEnabled'],
        'sharkPlatformType': !(0, runtime_1.exists)(json, 'SharkPlatformType') ? undefined : json['SharkPlatformType'],
        'sharkPassword': !(0, runtime_1.exists)(json, 'SharkPassword') ? undefined : json['SharkPassword'],
        'sharkBridgeUrl': !(0, runtime_1.exists)(json, 'SharkBridgeUrl') ? undefined : json['SharkBridgeUrl'],
    };
}
exports.SharkModelFromJSONTyped = SharkModelFromJSONTyped;
function SharkModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'IsSharkEnabled': value.isSharkEnabled,
        'SharkPlatformType': value.sharkPlatformType,
        'SharkPassword': value.sharkPassword,
        'SharkBridgeUrl': value.sharkBridgeUrl,
    };
}
exports.SharkModelToJSON = SharkModelToJSON;
//# sourceMappingURL=SharkModel.js.map