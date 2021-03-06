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
exports.IntegrationUserMappingItemModel = void 0;
/**
* Represents a model that carrying user mapping data.
*/
class IntegrationUserMappingItemModel {
    static getAttributeTypeMap() {
        return IntegrationUserMappingItemModel.attributeTypeMap;
    }
}
exports.IntegrationUserMappingItemModel = IntegrationUserMappingItemModel;
IntegrationUserMappingItemModel.discriminator = undefined;
IntegrationUserMappingItemModel.attributeTypeMap = [
    {
        "name": "email",
        "baseName": "Email",
        "type": "string"
    },
    {
        "name": "id",
        "baseName": "Id",
        "type": "string"
    },
    {
        "name": "integrationSystem",
        "baseName": "IntegrationSystem",
        "type": "IntegrationUserMappingItemModel.IntegrationSystemEnum"
    },
    {
        "name": "integrationUserName",
        "baseName": "IntegrationUserName",
        "type": "string"
    },
    {
        "name": "isEdit",
        "baseName": "IsEdit",
        "type": "boolean"
    },
    {
        "name": "name",
        "baseName": "Name",
        "type": "string"
    },
    {
        "name": "nameEmail",
        "baseName": "NameEmail",
        "type": "string"
    },
    {
        "name": "result",
        "baseName": "Result",
        "type": "IntegrationUserMappingItemModel.ResultEnum"
    },
    {
        "name": "userId",
        "baseName": "UserId",
        "type": "string"
    }
];
(function (IntegrationUserMappingItemModel) {
    let IntegrationSystemEnum;
    (function (IntegrationSystemEnum) {
        IntegrationSystemEnum[IntegrationSystemEnum["Teamcity"] = 'Teamcity'] = "Teamcity";
        IntegrationSystemEnum[IntegrationSystemEnum["Jenkins"] = 'Jenkins'] = "Jenkins";
        IntegrationSystemEnum[IntegrationSystemEnum["Bamboo"] = 'Bamboo'] = "Bamboo";
        IntegrationSystemEnum[IntegrationSystemEnum["GitLab"] = 'GitLab'] = "GitLab";
        IntegrationSystemEnum[IntegrationSystemEnum["AzureDevOps"] = 'AzureDevOps'] = "AzureDevOps";
        IntegrationSystemEnum[IntegrationSystemEnum["Jira"] = 'Jira'] = "Jira";
        IntegrationSystemEnum[IntegrationSystemEnum["CircleCi"] = 'CircleCI'] = "CircleCi";
        IntegrationSystemEnum[IntegrationSystemEnum["TravisCi"] = 'TravisCI'] = "TravisCi";
        IntegrationSystemEnum[IntegrationSystemEnum["UrbanCodeDeploy"] = 'UrbanCodeDeploy'] = "UrbanCodeDeploy";
        IntegrationSystemEnum[IntegrationSystemEnum["GitHubActions"] = 'GitHubActions'] = "GitHubActions";
    })(IntegrationSystemEnum = IntegrationUserMappingItemModel.IntegrationSystemEnum || (IntegrationUserMappingItemModel.IntegrationSystemEnum = {}));
    let ResultEnum;
    (function (ResultEnum) {
        ResultEnum[ResultEnum["NotFound"] = 'NotFound'] = "NotFound";
        ResultEnum[ResultEnum["BadRequest"] = 'BadRequest'] = "BadRequest";
        ResultEnum[ResultEnum["Duplicate"] = 'Duplicate'] = "Duplicate";
        ResultEnum[ResultEnum["Saved"] = 'Saved'] = "Saved";
        ResultEnum[ResultEnum["Edited"] = 'Edited'] = "Edited";
        ResultEnum[ResultEnum["Deleted"] = 'Deleted'] = "Deleted";
        ResultEnum[ResultEnum["Exist"] = 'Exist'] = "Exist";
    })(ResultEnum = IntegrationUserMappingItemModel.ResultEnum || (IntegrationUserMappingItemModel.ResultEnum = {}));
})(IntegrationUserMappingItemModel = exports.IntegrationUserMappingItemModel || (exports.IntegrationUserMappingItemModel = {}));
//# sourceMappingURL=integrationUserMappingItemModel.js.map