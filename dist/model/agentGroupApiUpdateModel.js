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
exports.AgentGroupApiUpdateModel = void 0;
/**
* Agent group model for updating
*/
class AgentGroupApiUpdateModel {
    static getAttributeTypeMap() {
        return AgentGroupApiUpdateModel.attributeTypeMap;
    }
}
exports.AgentGroupApiUpdateModel = AgentGroupApiUpdateModel;
AgentGroupApiUpdateModel.discriminator = undefined;
AgentGroupApiUpdateModel.attributeTypeMap = [
    {
        "name": "agents",
        "baseName": "Agents",
        "type": "Array<string>"
    },
    {
        "name": "id",
        "baseName": "Id",
        "type": "string"
    },
    {
        "name": "name",
        "baseName": "Name",
        "type": "string"
    }
];
//# sourceMappingURL=agentGroupApiUpdateModel.js.map