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
exports.FreshserviceEntityToJSON = exports.FreshserviceEntityFromJSONTyped = exports.FreshserviceEntityFromJSON = exports.instanceOfFreshserviceEntity = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the FreshserviceEntity interface.
 */
function instanceOfFreshserviceEntity(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfFreshserviceEntity = instanceOfFreshserviceEntity;
function FreshserviceEntityFromJSON(json) {
    return FreshserviceEntityFromJSONTyped(json, false);
}
exports.FreshserviceEntityFromJSON = FreshserviceEntityFromJSON;
function FreshserviceEntityFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'id': !(0, runtime_1.exists)(json, 'id') ? undefined : json['id'],
        'name': !(0, runtime_1.exists)(json, 'name') ? undefined : json['name'],
    };
}
exports.FreshserviceEntityFromJSONTyped = FreshserviceEntityFromJSONTyped;
function FreshserviceEntityToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'id': value.id,
        'name': value.name,
    };
}
exports.FreshserviceEntityToJSON = FreshserviceEntityToJSON;
//# sourceMappingURL=FreshserviceEntity.js.map