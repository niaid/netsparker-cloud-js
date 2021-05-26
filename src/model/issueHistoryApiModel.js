"use strict";
/**
 * Netsparker Enterprise API
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
exports.IssueHistoryApiModel = void 0;
/**
* Model for issue api history prop
*/
class IssueHistoryApiModel {
    static getAttributeTypeMap() {
        return IssueHistoryApiModel.attributeTypeMap;
    }
}
exports.IssueHistoryApiModel = IssueHistoryApiModel;
IssueHistoryApiModel.discriminator = undefined;
IssueHistoryApiModel.attributeTypeMap = [
    {
        "name": "message",
        "baseName": "Message",
        "type": "string"
    },
    {
        "name": "note",
        "baseName": "Note",
        "type": "string"
    },
    {
        "name": "owner",
        "baseName": "Owner",
        "type": "string"
    },
    {
        "name": "date",
        "baseName": "Date",
        "type": "string"
    }
];
//# sourceMappingURL=issueHistoryApiModel.js.map