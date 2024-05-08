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
exports.FreshServiceUserAgentToJSON = exports.FreshServiceUserAgentFromJSONTyped = exports.FreshServiceUserAgentFromJSON = exports.instanceOfFreshServiceUserAgent = void 0;
/**
 * Check if a given object implements the FreshServiceUserAgent interface.
 */
function instanceOfFreshServiceUserAgent(value) {
    return true;
}
exports.instanceOfFreshServiceUserAgent = instanceOfFreshServiceUserAgent;
function FreshServiceUserAgentFromJSON(json) {
    return FreshServiceUserAgentFromJSONTyped(json, false);
}
exports.FreshServiceUserAgentFromJSON = FreshServiceUserAgentFromJSON;
function FreshServiceUserAgentFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'firstName': json['first_name'] == null ? undefined : json['first_name'],
        'name': json['name'] == null ? undefined : json['name'],
        'email': json['email'] == null ? undefined : json['email'],
        'id': json['id'] == null ? undefined : json['id'],
    };
}
exports.FreshServiceUserAgentFromJSONTyped = FreshServiceUserAgentFromJSONTyped;
function FreshServiceUserAgentToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'first_name': value['firstName'],
        'name': value['name'],
        'email': value['email'],
        'id': value['id'],
    };
}
exports.FreshServiceUserAgentToJSON = FreshServiceUserAgentToJSON;
//# sourceMappingURL=FreshServiceUserAgent.js.map