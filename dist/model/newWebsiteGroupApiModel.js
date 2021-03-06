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
exports.NewWebsiteGroupApiModel = void 0;
/**
* Represents a model for creating a new website group.
*/
class NewWebsiteGroupApiModel {
    static getAttributeTypeMap() {
        return NewWebsiteGroupApiModel.attributeTypeMap;
    }
}
exports.NewWebsiteGroupApiModel = NewWebsiteGroupApiModel;
NewWebsiteGroupApiModel.discriminator = undefined;
NewWebsiteGroupApiModel.attributeTypeMap = [
    {
        "name": "name",
        "baseName": "Name",
        "type": "string"
    },
    {
        "name": "description",
        "baseName": "Description",
        "type": "string"
    }
];
//# sourceMappingURL=newWebsiteGroupApiModel.js.map