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
    if (!('integrationSystem' in value))
        return false;
    if (!('integrationUserName' in value))
        return false;
    if (!('userId' in value))
        return false;
    return true;
}
exports.instanceOfIntegrationUserMappingItemModel = instanceOfIntegrationUserMappingItemModel;
function IntegrationUserMappingItemModelFromJSON(json) {
    return IntegrationUserMappingItemModelFromJSONTyped(json, false);
}
exports.IntegrationUserMappingItemModelFromJSON = IntegrationUserMappingItemModelFromJSON;
function IntegrationUserMappingItemModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'email': json['Email'] == null ? undefined : json['Email'],
        'id': json['Id'] == null ? undefined : json['Id'],
        'integrationSystem': json['IntegrationSystem'],
        'integrationUserName': json['IntegrationUserName'],
        'isEdit': json['IsEdit'] == null ? undefined : json['IsEdit'],
        'name': json['Name'] == null ? undefined : json['Name'],
        'nameEmail': json['NameEmail'] == null ? undefined : json['NameEmail'],
        'result': json['Result'] == null ? undefined : json['Result'],
        'userId': json['UserId'],
    };
}
exports.IntegrationUserMappingItemModelFromJSONTyped = IntegrationUserMappingItemModelFromJSONTyped;
function IntegrationUserMappingItemModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Email': value['email'],
        'Id': value['id'],
        'IntegrationSystem': value['integrationSystem'],
        'IntegrationUserName': value['integrationUserName'],
        'IsEdit': value['isEdit'],
        'Name': value['name'],
        'Result': value['result'],
        'UserId': value['userId'],
    };
}
exports.IntegrationUserMappingItemModelToJSON = IntegrationUserMappingItemModelToJSON;
//# sourceMappingURL=IntegrationUserMappingItemModel.js.map