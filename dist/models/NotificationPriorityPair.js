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
exports.NotificationPriorityPairToJSON = exports.NotificationPriorityPairFromJSONTyped = exports.NotificationPriorityPairFromJSON = exports.instanceOfNotificationPriorityPair = void 0;
/**
 * Check if a given object implements the NotificationPriorityPair interface.
 */
function instanceOfNotificationPriorityPair(value) {
    return true;
}
exports.instanceOfNotificationPriorityPair = instanceOfNotificationPriorityPair;
function NotificationPriorityPairFromJSON(json) {
    return NotificationPriorityPairFromJSONTyped(json, false);
}
exports.NotificationPriorityPairFromJSON = NotificationPriorityPairFromJSON;
function NotificationPriorityPairFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'id': json['Id'] == null ? undefined : json['Id'],
        'priority': json['Priority'] == null ? undefined : json['Priority'],
    };
}
exports.NotificationPriorityPairFromJSONTyped = NotificationPriorityPairFromJSONTyped;
function NotificationPriorityPairToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Id': value['id'],
        'Priority': value['priority'],
    };
}
exports.NotificationPriorityPairToJSON = NotificationPriorityPairToJSON;
//# sourceMappingURL=NotificationPriorityPair.js.map