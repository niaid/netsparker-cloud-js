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
import type { IdNamePair } from './IdNamePair';
import {
    IdNamePairFromJSON,
    IdNamePairFromJSONTyped,
    IdNamePairToJSON,
} from './IdNamePair';

/**
 * Represents a model for carrying out website data.
 * @export
 * @interface WebsiteApiModel
 */
export interface WebsiteApiModel {
    /**
     * Gets or sets the website identifier.
     * @type {string}
     * @memberof WebsiteApiModel
     */
    id?: string;
    /**
     * Gets or sets the date which this website was created at.
     * @type {Date}
     * @memberof WebsiteApiModel
     */
    createdAt?: Date;
    /**
     * Gets or sets the date which this website was updated at.
     * @type {Date}
     * @memberof WebsiteApiModel
     */
    updatedAt?: Date;
    /**
     * Gets or sets the root domain URL.
     * @type {string}
     * @memberof WebsiteApiModel
     */
    rootUrl?: string;
    /**
     * Gets or sets a name for this website.
     * @type {string}
     * @memberof WebsiteApiModel
     */
    name?: string;
    /**
     * Gets or sets a name for this description.
     * @type {string}
     * @memberof WebsiteApiModel
     */
    description?: string;
    /**
     * Gets or sets the technical contact email.
     * @type {string}
     * @memberof WebsiteApiModel
     */
    technicalContactEmail?: string;
    /**
     * Gets or sets the name of groups this website will belong to.
     * @type {Array<IdNamePair>}
     * @memberof WebsiteApiModel
     */
    groups?: Array<IdNamePair>;
    /**
     * Gets or sets a value indicating whether this website is verified.
     * @type {boolean}
     * @memberof WebsiteApiModel
     */
    isVerified?: boolean;
    /**
     * Gets or sets the type of the subscription.
     * @type {string}
     * @memberof WebsiteApiModel
     */
    licenseType?: WebsiteApiModelLicenseTypeEnum;
    /**
     * Gets or sets the agent mode.
     * @type {string}
     * @memberof WebsiteApiModel
     */
    agentMode?: WebsiteApiModelAgentModeEnum;
    /**
     * Tags
     * @type {Array<string>}
     * @memberof WebsiteApiModel
     */
    tags?: Array<string>;
}


/**
 * @export
 */
export const WebsiteApiModelLicenseTypeEnum = {
    Subscription: 'Subscription',
    Credit: 'Credit'
} as const;
export type WebsiteApiModelLicenseTypeEnum = typeof WebsiteApiModelLicenseTypeEnum[keyof typeof WebsiteApiModelLicenseTypeEnum];

/**
 * @export
 */
export const WebsiteApiModelAgentModeEnum = {
    Cloud: 'Cloud',
    Internal: 'Internal'
} as const;
export type WebsiteApiModelAgentModeEnum = typeof WebsiteApiModelAgentModeEnum[keyof typeof WebsiteApiModelAgentModeEnum];


/**
 * Check if a given object implements the WebsiteApiModel interface.
 */
export function instanceOfWebsiteApiModel(value: object): boolean {
    return true;
}

export function WebsiteApiModelFromJSON(json: any): WebsiteApiModel {
    return WebsiteApiModelFromJSONTyped(json, false);
}

export function WebsiteApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): WebsiteApiModel {
    if (json == null) {
        return json;
    }
    return {
        
        'id': json['Id'] == null ? undefined : json['Id'],
        'createdAt': json['CreatedAt'] == null ? undefined : (new Date(json['CreatedAt'])),
        'updatedAt': json['UpdatedAt'] == null ? undefined : (new Date(json['UpdatedAt'])),
        'rootUrl': json['RootUrl'] == null ? undefined : json['RootUrl'],
        'name': json['Name'] == null ? undefined : json['Name'],
        'description': json['Description'] == null ? undefined : json['Description'],
        'technicalContactEmail': json['TechnicalContactEmail'] == null ? undefined : json['TechnicalContactEmail'],
        'groups': json['Groups'] == null ? undefined : ((json['Groups'] as Array<any>).map(IdNamePairFromJSON)),
        'isVerified': json['IsVerified'] == null ? undefined : json['IsVerified'],
        'licenseType': json['LicenseType'] == null ? undefined : json['LicenseType'],
        'agentMode': json['AgentMode'] == null ? undefined : json['AgentMode'],
        'tags': json['Tags'] == null ? undefined : json['Tags'],
    };
}

export function WebsiteApiModelToJSON(value?: WebsiteApiModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Id': value['id'],
        'CreatedAt': value['createdAt'] == null ? undefined : ((value['createdAt']).toISOString()),
        'UpdatedAt': value['updatedAt'] == null ? undefined : ((value['updatedAt']).toISOString()),
        'RootUrl': value['rootUrl'],
        'Name': value['name'],
        'Description': value['description'],
        'TechnicalContactEmail': value['technicalContactEmail'],
        'Groups': value['groups'] == null ? undefined : ((value['groups'] as Array<any>).map(IdNamePairToJSON)),
        'IsVerified': value['isVerified'],
        'LicenseType': value['licenseType'],
        'AgentMode': value['agentMode'],
        'Tags': value['tags'],
    };
}

