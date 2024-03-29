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

import { exists, mapValues } from '../runtime';
/**
 * Represents a model for carrying out website groups data.
 * @export
 * @interface WebsiteGroupModel
 */
export interface WebsiteGroupModel {
    /**
     * Gets the display name.
     * @type {string}
     * @memberof WebsiteGroupModel
     */
    readonly displayName?: string;
    /**
     * Gets or sets the group identifier.
     * @type {string}
     * @memberof WebsiteGroupModel
     */
    id?: string;
    /**
     * Gets or sets the group name.
     * @type {string}
     * @memberof WebsiteGroupModel
     */
    name?: string;
    /**
     * Gets or sets the not verified website count.
     * @type {number}
     * @memberof WebsiteGroupModel
     */
    notVerifiedWebsiteCount?: number;
    /**
     * Gets or sets the verified website count.
     * @type {number}
     * @memberof WebsiteGroupModel
     */
    verifiedWebsiteCount?: number;
}

/**
 * Check if a given object implements the WebsiteGroupModel interface.
 */
export function instanceOfWebsiteGroupModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function WebsiteGroupModelFromJSON(json: any): WebsiteGroupModel {
    return WebsiteGroupModelFromJSONTyped(json, false);
}

export function WebsiteGroupModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): WebsiteGroupModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'displayName': !exists(json, 'DisplayName') ? undefined : json['DisplayName'],
        'id': !exists(json, 'Id') ? undefined : json['Id'],
        'name': !exists(json, 'Name') ? undefined : json['Name'],
        'notVerifiedWebsiteCount': !exists(json, 'NotVerifiedWebsiteCount') ? undefined : json['NotVerifiedWebsiteCount'],
        'verifiedWebsiteCount': !exists(json, 'VerifiedWebsiteCount') ? undefined : json['VerifiedWebsiteCount'],
    };
}

export function WebsiteGroupModelToJSON(value?: WebsiteGroupModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Id': value.id,
        'Name': value.name,
        'NotVerifiedWebsiteCount': value.notVerifiedWebsiteCount,
        'VerifiedWebsiteCount': value.verifiedWebsiteCount,
    };
}

