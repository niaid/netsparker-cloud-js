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
exports.UpdateRoleApiModel = void 0;
class UpdateRoleApiModel {
    static getAttributeTypeMap() {
        return UpdateRoleApiModel.attributeTypeMap;
    }
}
exports.UpdateRoleApiModel = UpdateRoleApiModel;
UpdateRoleApiModel.discriminator = undefined;
UpdateRoleApiModel.attributeTypeMap = [
    {
        "name": "id",
        "baseName": "Id",
        "type": "string"
    },
    {
        "name": "name",
        "baseName": "Name",
        "type": "string"
    },
    {
        "name": "permissions",
        "baseName": "Permissions",
        "type": "Array<string>"
    }
];
//# sourceMappingURL=updateRoleApiModel.js.map