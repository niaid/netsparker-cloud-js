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
exports.ServiceNowIntegrationInfoModelFieldMappingsDictionaryToJSON = exports.ServiceNowIntegrationInfoModelFieldMappingsDictionaryFromJSONTyped = exports.ServiceNowIntegrationInfoModelFieldMappingsDictionaryFromJSON = exports.instanceOfServiceNowIntegrationInfoModelFieldMappingsDictionary = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the ServiceNowIntegrationInfoModelFieldMappingsDictionary interface.
 */
function instanceOfServiceNowIntegrationInfoModelFieldMappingsDictionary(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfServiceNowIntegrationInfoModelFieldMappingsDictionary = instanceOfServiceNowIntegrationInfoModelFieldMappingsDictionary;
function ServiceNowIntegrationInfoModelFieldMappingsDictionaryFromJSON(json) {
    return ServiceNowIntegrationInfoModelFieldMappingsDictionaryFromJSONTyped(json, false);
}
exports.ServiceNowIntegrationInfoModelFieldMappingsDictionaryFromJSON = ServiceNowIntegrationInfoModelFieldMappingsDictionaryFromJSON;
function ServiceNowIntegrationInfoModelFieldMappingsDictionaryFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'severity': !(0, runtime_1.exists)(json, 'Severity') ? undefined : json['Severity'],
    };
}
exports.ServiceNowIntegrationInfoModelFieldMappingsDictionaryFromJSONTyped = ServiceNowIntegrationInfoModelFieldMappingsDictionaryFromJSONTyped;
function ServiceNowIntegrationInfoModelFieldMappingsDictionaryToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Severity': value.severity,
    };
}
exports.ServiceNowIntegrationInfoModelFieldMappingsDictionaryToJSON = ServiceNowIntegrationInfoModelFieldMappingsDictionaryToJSON;
//# sourceMappingURL=ServiceNowIntegrationInfoModelFieldMappingsDictionary.js.map