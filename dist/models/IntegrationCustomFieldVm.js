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
exports.IntegrationCustomFieldVmToJSON = exports.IntegrationCustomFieldVmFromJSONTyped = exports.IntegrationCustomFieldVmFromJSON = exports.instanceOfIntegrationCustomFieldVm = exports.IntegrationCustomFieldVmInputTypeEnum = void 0;
const runtime_1 = require("../runtime");
const FileCache_1 = require("./FileCache");
/**
 * @export
 */
exports.IntegrationCustomFieldVmInputTypeEnum = {
    Text: 'Text',
    Password: 'Password',
    Textarea: 'Textarea',
    FileUpload: 'FileUpload',
    Complex: 'Complex'
};
/**
 * Check if a given object implements the IntegrationCustomFieldVm interface.
 */
function instanceOfIntegrationCustomFieldVm(value) {
    let isInstance = true;
    isInstance = isInstance && "name" in value;
    return isInstance;
}
exports.instanceOfIntegrationCustomFieldVm = instanceOfIntegrationCustomFieldVm;
function IntegrationCustomFieldVmFromJSON(json) {
    return IntegrationCustomFieldVmFromJSONTyped(json, false);
}
exports.IntegrationCustomFieldVmFromJSON = IntegrationCustomFieldVmFromJSON;
function IntegrationCustomFieldVmFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'file': !(0, runtime_1.exists)(json, 'File') ? undefined : (0, FileCache_1.FileCacheFromJSON)(json['File']),
        'name': json['Name'],
        'value': !(0, runtime_1.exists)(json, 'Value') ? undefined : json['Value'],
        'inputType': !(0, runtime_1.exists)(json, 'InputType') ? undefined : json['InputType'],
    };
}
exports.IntegrationCustomFieldVmFromJSONTyped = IntegrationCustomFieldVmFromJSONTyped;
function IntegrationCustomFieldVmToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'File': (0, FileCache_1.FileCacheToJSON)(value.file),
        'Name': value.name,
        'Value': value.value,
        'InputType': value.inputType,
    };
}
exports.IntegrationCustomFieldVmToJSON = IntegrationCustomFieldVmToJSON;
//# sourceMappingURL=IntegrationCustomFieldVm.js.map