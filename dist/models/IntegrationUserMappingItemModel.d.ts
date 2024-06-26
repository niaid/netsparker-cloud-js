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
/**
 * Represents a model that carrying user mapping data.
 * @export
 * @interface IntegrationUserMappingItemModel
 */
export interface IntegrationUserMappingItemModel {
    /**
     * Gets or sets the user email
     * @type {string}
     * @memberof IntegrationUserMappingItemModel
     */
    email?: string;
    /**
     * Gets or sets the user mapping Id.
     * @type {string}
     * @memberof IntegrationUserMappingItemModel
     */
    id?: string;
    /**
     * Gets or sets the integration system.
     * @type {string}
     * @memberof IntegrationUserMappingItemModel
     */
    integrationSystem: IntegrationUserMappingItemModelIntegrationSystemEnum;
    /**
     * Gets or sets the user's integration name.
     * @type {string}
     * @memberof IntegrationUserMappingItemModel
     */
    integrationUserName: string;
    /**
     * Gets or sets whether the user mapping is requested for editing
     * @type {boolean}
     * @memberof IntegrationUserMappingItemModel
     */
    isEdit?: boolean;
    /**
     * Gets or sets the user name
     * @type {string}
     * @memberof IntegrationUserMappingItemModel
     */
    name?: string;
    /**
     * Gets the user's nc name in "Name (Email)" format.
     * @type {string}
     * @memberof IntegrationUserMappingItemModel
     */
    readonly nameEmail?: string;
    /**
     * Gets the user mapping item result enum.
     * @type {string}
     * @memberof IntegrationUserMappingItemModel
     */
    result?: IntegrationUserMappingItemModelResultEnum;
    /**
     * Gets or sets the user Id
     * @type {string}
     * @memberof IntegrationUserMappingItemModel
     */
    userId: string;
}
/**
 * @export
 */
export declare const IntegrationUserMappingItemModelIntegrationSystemEnum: {
    readonly Teamcity: "Teamcity";
    readonly Jenkins: "Jenkins";
    readonly Bamboo: "Bamboo";
    readonly GitLab: "GitLab";
    readonly AzureDevOps: "AzureDevOps";
    readonly Jira: "Jira";
    readonly CircleCi: "CircleCI";
    readonly TravisCi: "TravisCI";
    readonly UrbanCodeDeploy: "UrbanCodeDeploy";
    readonly GitHubActions: "GitHubActions";
};
export type IntegrationUserMappingItemModelIntegrationSystemEnum = typeof IntegrationUserMappingItemModelIntegrationSystemEnum[keyof typeof IntegrationUserMappingItemModelIntegrationSystemEnum];
/**
 * @export
 */
export declare const IntegrationUserMappingItemModelResultEnum: {
    readonly NotFound: "NotFound";
    readonly BadRequest: "BadRequest";
    readonly Duplicate: "Duplicate";
    readonly Saved: "Saved";
    readonly Edited: "Edited";
    readonly Deleted: "Deleted";
    readonly Exist: "Exist";
};
export type IntegrationUserMappingItemModelResultEnum = typeof IntegrationUserMappingItemModelResultEnum[keyof typeof IntegrationUserMappingItemModelResultEnum];
/**
 * Check if a given object implements the IntegrationUserMappingItemModel interface.
 */
export declare function instanceOfIntegrationUserMappingItemModel(value: object): boolean;
export declare function IntegrationUserMappingItemModelFromJSON(json: any): IntegrationUserMappingItemModel;
export declare function IntegrationUserMappingItemModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): IntegrationUserMappingItemModel;
export declare function IntegrationUserMappingItemModelToJSON(value?: Omit<IntegrationUserMappingItemModel, 'NameEmail'> | null): any;
