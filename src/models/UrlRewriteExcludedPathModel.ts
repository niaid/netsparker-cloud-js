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
 * Represents an URL Rewrite Exclude Path rule
 * @export
 * @interface UrlRewriteExcludedPathModel
 */
export interface UrlRewriteExcludedPathModel {
    /**
     * Gets or sets the excluded path.
     * @type {string}
     * @memberof UrlRewriteExcludedPathModel
     */
    excludedPath?: string;
    /**
     * Gets or sets a value indicating whether this instance is regex.
     * @type {boolean}
     * @memberof UrlRewriteExcludedPathModel
     */
    isRegex?: boolean;
}

/**
 * Check if a given object implements the UrlRewriteExcludedPathModel interface.
 */
export function instanceOfUrlRewriteExcludedPathModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function UrlRewriteExcludedPathModelFromJSON(json: any): UrlRewriteExcludedPathModel {
    return UrlRewriteExcludedPathModelFromJSONTyped(json, false);
}

export function UrlRewriteExcludedPathModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): UrlRewriteExcludedPathModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'excludedPath': !exists(json, 'ExcludedPath') ? undefined : json['ExcludedPath'],
        'isRegex': !exists(json, 'IsRegex') ? undefined : json['IsRegex'],
    };
}

export function UrlRewriteExcludedPathModelToJSON(value?: UrlRewriteExcludedPathModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'ExcludedPath': value.excludedPath,
        'IsRegex': value.isRegex,
    };
}

