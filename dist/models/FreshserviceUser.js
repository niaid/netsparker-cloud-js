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
exports.FreshserviceUserToJSON = exports.FreshserviceUserFromJSONTyped = exports.FreshserviceUserFromJSON = exports.instanceOfFreshserviceUser = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the FreshserviceUser interface.
 */
function instanceOfFreshserviceUser(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfFreshserviceUser = instanceOfFreshserviceUser;
function FreshserviceUserFromJSON(json) {
    return FreshserviceUserFromJSONTyped(json, false);
}
exports.FreshserviceUserFromJSON = FreshserviceUserFromJSON;
function FreshserviceUserFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'email': !(0, runtime_1.exists)(json, 'email') ? undefined : json['email'],
        'id': !(0, runtime_1.exists)(json, 'id') ? undefined : json['id'],
        'name': !(0, runtime_1.exists)(json, 'name') ? undefined : json['name'],
    };
}
exports.FreshserviceUserFromJSONTyped = FreshserviceUserFromJSONTyped;
function FreshserviceUserToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'email': value.email,
        'id': value.id,
        'name': value.name,
    };
}
exports.FreshserviceUserToJSON = FreshserviceUserToJSON;
//# sourceMappingURL=FreshserviceUser.js.map