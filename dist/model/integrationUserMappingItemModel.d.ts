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
/**
* Represents a model that carrying user mapping data.
*/
export declare class IntegrationUserMappingItemModel {
    /**
    * Gets or sets the user email
    */
    'email'?: string;
    /**
    * Gets or sets the user mapping Id.
    */
    'id'?: string;
    /**
    * Gets or sets the integration system.
    */
    'integrationSystem': IntegrationUserMappingItemModel.IntegrationSystemEnum;
    /**
    * Gets or sets the user\'s integration name.
    */
    'integrationUserName': string;
    /**
    * Gets or sets whether the user mapping is requested for editing
    */
    'isEdit'?: boolean;
    /**
    * Gets or sets the user name
    */
    'name'?: string;
    /**
    * Gets the user\'s nc name in \"Name (Email)\" format.
    */
    'nameEmail'?: string;
    /**
    * Gets the user mapping item result enum.
    */
    'result'?: IntegrationUserMappingItemModel.ResultEnum;
    /**
    * Gets or sets the user Id
    */
    'userId': string;
    static discriminator: string | undefined;
    static attributeTypeMap: Array<{
        name: string;
        baseName: string;
        type: string;
    }>;
    static getAttributeTypeMap(): {
        name: string;
        baseName: string;
        type: string;
    }[];
}
export declare namespace IntegrationUserMappingItemModel {
    enum IntegrationSystemEnum {
        Teamcity,
        Jenkins,
        Bamboo,
        GitLab,
        AzureDevOps,
        Jira,
        CircleCi,
        TravisCi,
        UrbanCodeDeploy,
        GitHubActions
    }
    enum ResultEnum {
        NotFound,
        BadRequest,
        Duplicate,
        Saved,
        Edited,
        Deleted,
        Exist
    }
}
