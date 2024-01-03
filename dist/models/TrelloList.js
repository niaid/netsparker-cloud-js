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
exports.TrelloListToJSON = exports.TrelloListFromJSONTyped = exports.TrelloListFromJSON = exports.instanceOfTrelloList = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the TrelloList interface.
 */
function instanceOfTrelloList(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfTrelloList = instanceOfTrelloList;
function TrelloListFromJSON(json) {
    return TrelloListFromJSONTyped(json, false);
}
exports.TrelloListFromJSON = TrelloListFromJSON;
function TrelloListFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'closed': !(0, runtime_1.exists)(json, 'closed') ? undefined : json['closed'],
        'id': !(0, runtime_1.exists)(json, 'id') ? undefined : json['id'],
        'isActive': !(0, runtime_1.exists)(json, 'IsActive') ? undefined : json['IsActive'],
        'name': !(0, runtime_1.exists)(json, 'name') ? undefined : json['name'],
    };
}
exports.TrelloListFromJSONTyped = TrelloListFromJSONTyped;
function TrelloListToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'closed': value.closed,
        'id': value.id,
        'name': value.name,
    };
}
exports.TrelloListToJSON = TrelloListToJSON;
//# sourceMappingURL=TrelloList.js.map