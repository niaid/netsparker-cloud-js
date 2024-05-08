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
 * Represents a model for updating a new website group.
 * @export
 * @interface UpdateWebsiteGroupApiModel
 */
export interface UpdateWebsiteGroupApiModel {
    /**
     * Gets or sets the website group identifier.
     * @type {string}
     * @memberof UpdateWebsiteGroupApiModel
     */
    id: string;
    /**
     * Gets or sets the website group name.
     * @type {string}
     * @memberof UpdateWebsiteGroupApiModel
     */
    name: string;
    /**
     * Gets or sets the website group description.
     * @type {string}
     * @memberof UpdateWebsiteGroupApiModel
     */
    description?: string;
    /**
     * Tags
     * @type {Array<string>}
     * @memberof UpdateWebsiteGroupApiModel
     */
    tags?: Array<string>;
}

/**
 * Check if a given object implements the UpdateWebsiteGroupApiModel interface.
 */
export function instanceOfUpdateWebsiteGroupApiModel(value: object): boolean {
    if (!('id' in value)) return false;
    if (!('name' in value)) return false;
    return true;
}

export function UpdateWebsiteGroupApiModelFromJSON(json: any): UpdateWebsiteGroupApiModel {
    return UpdateWebsiteGroupApiModelFromJSONTyped(json, false);
}

export function UpdateWebsiteGroupApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): UpdateWebsiteGroupApiModel {
    if (json == null) {
        return json;
    }
    return {
        
        'id': json['Id'],
        'name': json['Name'],
        'description': json['Description'] == null ? undefined : json['Description'],
        'tags': json['Tags'] == null ? undefined : json['Tags'],
    };
}

export function UpdateWebsiteGroupApiModelToJSON(value?: UpdateWebsiteGroupApiModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Id': value['id'],
        'Name': value['name'],
        'Description': value['description'],
        'Tags': value['tags'],
    };
}

