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
exports.IntegrationUserMappingItemModelToJSON = exports.IntegrationUserMappingItemModelFromJSONTyped = exports.IntegrationUserMappingItemModelFromJSON = exports.instanceOfIntegrationUserMappingItemModel = exports.IntegrationUserMappingItemModelResultEnum = exports.IntegrationUserMappingItemModelIntegrationSystemEnum = void 0;
const runtime_1 = require("../runtime");
/**
 * @export
 */
exports.IntegrationUserMappingItemModelIntegrationSystemEnum = {
    Teamcity: 'Teamcity',
    Jenkins: 'Jenkins',
    Bamboo: 'Bamboo',
    GitLab: 'GitLab',
    AzureDevOps: 'AzureDevOps',
    Jira: 'Jira',
    CircleCi: 'CircleCI',
    TravisCi: 'TravisCI',
    UrbanCodeDeploy: 'UrbanCodeDeploy',
    GitHubActions: 'GitHubActions'
};
/**
 * @export
 */
exports.IntegrationUserMappingItemModelResultEnum = {
    NotFound: 'NotFound',
    BadRequest: 'BadRequest',
    Duplicate: 'Duplicate',
    Saved: 'Saved',
    Edited: 'Edited',
    Deleted: 'Deleted',
    Exist: 'Exist'
};
/**
 * Check if a given object implements the IntegrationUserMappingItemModel interface.
 */
function instanceOfIntegrationUserMappingItemModel(value) {
    let isInstance = true;
    isInstance = isInstance && "integrationSystem" in value;
    isInstance = isInstance && "integrationUserName" in value;
    isInstance = isInstance && "userId" in value;
    return isInstance;
}
exports.instanceOfIntegrationUserMappingItemModel = instanceOfIntegrationUserMappingItemModel;
function IntegrationUserMappingItemModelFromJSON(json) {
    return IntegrationUserMappingItemModelFromJSONTyped(json, false);
}
exports.IntegrationUserMappingItemModelFromJSON = IntegrationUserMappingItemModelFromJSON;
function IntegrationUserMappingItemModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'email': !(0, runtime_1.exists)(json, 'Email') ? undefined : json['Email'],
        'id': !(0, runtime_1.exists)(json, 'Id') ? undefined : json['Id'],
        'integrationSystem': json['IntegrationSystem'],
        'integrationUserName': json['IntegrationUserName'],
        'isEdit': !(0, runtime_1.exists)(json, 'IsEdit') ? undefined : json['IsEdit'],
        'name': !(0, runtime_1.exists)(json, 'Name') ? undefined : json['Name'],
        'nameEmail': !(0, runtime_1.exists)(json, 'NameEmail') ? undefined : json['NameEmail'],
        'result': !(0, runtime_1.exists)(json, 'Result') ? undefined : json['Result'],
        'userId': json['UserId'],
    };
}
exports.IntegrationUserMappingItemModelFromJSONTyped = IntegrationUserMappingItemModelFromJSONTyped;
function IntegrationUserMappingItemModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Email': value.email,
        'Id': value.id,
        'IntegrationSystem': value.integrationSystem,
        'IntegrationUserName': value.integrationUserName,
        'IsEdit': value.isEdit,
        'Name': value.name,
        'Result': value.result,
        'UserId': value.userId,
    };
}
exports.IntegrationUserMappingItemModelToJSON = IntegrationUserMappingItemModelToJSON;
//# sourceMappingURL=IntegrationUserMappingItemModel.js.map