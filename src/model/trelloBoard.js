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
class TrelloBoard {
    static getAttributeTypeMap() {
        return TrelloBoard.attributeTypeMap;
    }
}
TrelloBoard.discriminator = undefined;
TrelloBoard.attributeTypeMap = [
    {
        "name": "closed",
        "baseName": "closed",
        "type": "boolean"
    },
    {
        "name": "id",
        "baseName": "id",
        "type": "string"
    },
    {
        "name": "isActive",
        "baseName": "IsActive",
        "type": "boolean"
    },
    {
        "name": "name",
        "baseName": "name",
        "type": "string"
    },
    {
        "name": "shortUrl",
        "baseName": "shortUrl",
        "type": "string"
    }
];
exports.TrelloBoard = TrelloBoard;
//# sourceMappingURL=trelloBoard.js.map