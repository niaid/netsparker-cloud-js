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
import type { FileCache } from './FileCache';
import {
    FileCacheFromJSON,
    FileCacheFromJSONTyped,
    FileCacheToJSON,
} from './FileCache';

/**
 * Represents a class that carries out imported links.
 * @export
 * @interface ImportedLinksSetting
 */
export interface ImportedLinksSetting {
    /**
     * Gets or sets the imported files.
     * @type {Array<FileCache>}
     * @memberof ImportedLinksSetting
     */
    importedFiles?: Array<FileCache>;
    /**
     * Gets or sets the imported links.
     * @type {string}
     * @memberof ImportedLinksSetting
     */
    importedLinks?: string;
    /**
     * 
     * @type {string}
     * @memberof ImportedLinksSetting
     */
    importedURL?: string;
}

/**
 * Check if a given object implements the ImportedLinksSetting interface.
 */
export function instanceOfImportedLinksSetting(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function ImportedLinksSettingFromJSON(json: any): ImportedLinksSetting {
    return ImportedLinksSettingFromJSONTyped(json, false);
}

export function ImportedLinksSettingFromJSONTyped(json: any, ignoreDiscriminator: boolean): ImportedLinksSetting {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'importedFiles': !exists(json, 'ImportedFiles') ? undefined : ((json['ImportedFiles'] as Array<any>).map(FileCacheFromJSON)),
        'importedLinks': !exists(json, 'ImportedLinks') ? undefined : json['ImportedLinks'],
        'importedURL': !exists(json, 'ImportedURL') ? undefined : json['ImportedURL'],
    };
}

export function ImportedLinksSettingToJSON(value?: ImportedLinksSetting | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'ImportedFiles': value.importedFiles === undefined ? undefined : ((value.importedFiles as Array<any>).map(FileCacheToJSON)),
        'ImportedLinks': value.importedLinks,
        'ImportedURL': value.importedURL,
    };
}
