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
exports.TrelloLabelToJSON = exports.TrelloLabelFromJSONTyped = exports.TrelloLabelFromJSON = exports.instanceOfTrelloLabel = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the TrelloLabel interface.
 */
function instanceOfTrelloLabel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfTrelloLabel = instanceOfTrelloLabel;
function TrelloLabelFromJSON(json) {
    return TrelloLabelFromJSONTyped(json, false);
}
exports.TrelloLabelFromJSON = TrelloLabelFromJSON;
function TrelloLabelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'color': !(0, runtime_1.exists)(json, 'color') ? undefined : json['color'],
        'id': !(0, runtime_1.exists)(json, 'id') ? undefined : json['id'],
        'name': !(0, runtime_1.exists)(json, 'name') ? undefined : json['name'],
    };
}
exports.TrelloLabelFromJSONTyped = TrelloLabelFromJSONTyped;
function TrelloLabelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'color': value.color,
        'id': value.id,
        'name': value.name,
    };
}
exports.TrelloLabelToJSON = TrelloLabelToJSON;
//# sourceMappingURL=TrelloLabel.js.map