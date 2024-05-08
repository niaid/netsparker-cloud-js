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

import { mapValues } from '../runtime';
/**
 * Represents a model for creating a new website.
 * @export
 * @interface NewWebsiteApiModel
 */
export interface NewWebsiteApiModel {
    /**
     * Gets or sets the agent mode for the website.
     * @type {string}
     * @memberof NewWebsiteApiModel
     */
    agentMode?: NewWebsiteApiModelAgentModeEnum;
    /**
     * Gets or sets the root URL.
     * @type {string}
     * @memberof NewWebsiteApiModel
     */
    rootUrl: string;
    /**
     * Gets or sets the name of groups this website will belong to.
     * @type {Array<string>}
     * @memberof NewWebsiteApiModel
     */
    groups?: Array<string>;
    /**
     * Gets or sets the type of the subscription.
     * @type {string}
     * @memberof NewWebsiteApiModel
     */
    licenseType: NewWebsiteApiModelLicenseTypeEnum;
    /**
     * Gets or sets the website name.
     * @type {string}
     * @memberof NewWebsiteApiModel
     */
    name: string;
    /**
     * Gets or sets the website description.
     * @type {string}
     * @memberof NewWebsiteApiModel
     */
    description?: string;
    /**
     * Gets or sets the technical contact email.
     * @type {string}
     * @memberof NewWebsiteApiModel
     */
    technicalContactEmail?: string;
    /**
     * Gets or sets the tags
     * @type {Array<string>}
     * @memberof NewWebsiteApiModel
     */
    tags?: Array<string>;
}


/**
 * @export
 */
export const NewWebsiteApiModelAgentModeEnum = {
    Cloud: 'Cloud',
    Internal: 'Internal'
} as const;
export type NewWebsiteApiModelAgentModeEnum = typeof NewWebsiteApiModelAgentModeEnum[keyof typeof NewWebsiteApiModelAgentModeEnum];

/**
 * @export
 */
export const NewWebsiteApiModelLicenseTypeEnum = {
    Subscription: 'Subscription',
    Credit: 'Credit'
} as const;
export type NewWebsiteApiModelLicenseTypeEnum = typeof NewWebsiteApiModelLicenseTypeEnum[keyof typeof NewWebsiteApiModelLicenseTypeEnum];


/**
 * Check if a given object implements the NewWebsiteApiModel interface.
 */
export function instanceOfNewWebsiteApiModel(value: object): boolean {
    if (!('rootUrl' in value)) return false;
    if (!('licenseType' in value)) return false;
    if (!('name' in value)) return false;
    return true;
}

export function NewWebsiteApiModelFromJSON(json: any): NewWebsiteApiModel {
    return NewWebsiteApiModelFromJSONTyped(json, false);
}

export function NewWebsiteApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): NewWebsiteApiModel {
    if (json == null) {
        return json;
    }
    return {
        
        'agentMode': json['AgentMode'] == null ? undefined : json['AgentMode'],
        'rootUrl': json['RootUrl'],
        'groups': json['Groups'] == null ? undefined : json['Groups'],
        'licenseType': json['LicenseType'],
        'name': json['Name'],
        'description': json['Description'] == null ? undefined : json['Description'],
        'technicalContactEmail': json['TechnicalContactEmail'] == null ? undefined : json['TechnicalContactEmail'],
        'tags': json['Tags'] == null ? undefined : json['Tags'],
    };
}

export function NewWebsiteApiModelToJSON(value?: NewWebsiteApiModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'AgentMode': value['agentMode'],
        'RootUrl': value['rootUrl'],
        'Groups': value['groups'],
        'LicenseType': value['licenseType'],
        'Name': value['name'],
        'Description': value['description'],
        'TechnicalContactEmail': value['technicalContactEmail'],
        'Tags': value['tags'],
    };
}

