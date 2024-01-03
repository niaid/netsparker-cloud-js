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
import { exists } from '../runtime';
import { CustomHttpHeaderModelFromJSON, CustomHttpHeaderModelToJSON, } from './CustomHttpHeaderModel';
/**
 * Check if a given object implements the HeaderAuthenticationModel interface.
 */
export function instanceOfHeaderAuthenticationModel(value) {
    let isInstance = true;
    return isInstance;
}
export function HeaderAuthenticationModelFromJSON(json) {
    return HeaderAuthenticationModelFromJSONTyped(json, false);
}
export function HeaderAuthenticationModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'headers': !exists(json, 'Headers') ? undefined : (json['Headers'].map(CustomHttpHeaderModelFromJSON)),
        'isEnabled': !exists(json, 'IsEnabled') ? undefined : json['IsEnabled'],
    };
}
export function HeaderAuthenticationModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Headers': value.headers === undefined ? undefined : (value.headers.map(CustomHttpHeaderModelToJSON)),
        'IsEnabled': value.isEnabled,
    };
}
//# sourceMappingURL=HeaderAuthenticationModel.js.map