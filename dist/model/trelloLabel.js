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
exports.TrelloLabel = void 0;
class TrelloLabel {
    static getAttributeTypeMap() {
        return TrelloLabel.attributeTypeMap;
    }
}
exports.TrelloLabel = TrelloLabel;
TrelloLabel.discriminator = undefined;
TrelloLabel.attributeTypeMap = [
    {
        "name": "color",
        "baseName": "color",
        "type": "string"
    },
    {
        "name": "id",
        "baseName": "id",
        "type": "string"
    },
    {
        "name": "name",
        "baseName": "name",
        "type": "string"
    }
];
//# sourceMappingURL=trelloLabel.js.map