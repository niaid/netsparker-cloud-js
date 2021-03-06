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

import { RequestFile } from './models';
import { ExcludedLinkModel } from './excludedLinkModel';
import { ExcludedUsageTrackerModel } from './excludedUsageTrackerModel';

/**
* Represents a class that carries out scope settings.
*/
export class ScopeSetting {
    /**
    * Gets or sets the excluded links.
    */
    'excludedLinks'?: Array<ExcludedLinkModel>;
    /**
    * Gets or sets a value indicating whether links should be excluded/included.
    */
    'excludeLinks'?: boolean;
    /**
    * Gets or sets the excluded usage trackers.
    */
    'excludedUsageTrackers'?: Array<ExcludedUsageTrackerModel>;
    /**
    * Specifies whether the authentication related pages like login, logout etc. should be excluded from the scan..
    */
    'excludeAuthenticationPages'?: boolean;
    /**
    * Gets or sets the disallowed http methods.
    */
    'disallowedHttpMethods'?: Array<ScopeSetting.DisallowedHttpMethodsEnum>;
    /**
    * Gets or sets the scan scope.
    */
    'scope'?: ScopeSetting.ScopeEnum;
    /**
    * Gets or sets a value indicating whether http and https protocols are differentiated.
    */
    'doNotDifferentiateProtocols'?: boolean;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "excludedLinks",
            "baseName": "ExcludedLinks",
            "type": "Array<ExcludedLinkModel>"
        },
        {
            "name": "excludeLinks",
            "baseName": "ExcludeLinks",
            "type": "boolean"
        },
        {
            "name": "excludedUsageTrackers",
            "baseName": "ExcludedUsageTrackers",
            "type": "Array<ExcludedUsageTrackerModel>"
        },
        {
            "name": "excludeAuthenticationPages",
            "baseName": "ExcludeAuthenticationPages",
            "type": "boolean"
        },
        {
            "name": "disallowedHttpMethods",
            "baseName": "DisallowedHttpMethods",
            "type": "Array<ScopeSetting.DisallowedHttpMethodsEnum>"
        },
        {
            "name": "scope",
            "baseName": "Scope",
            "type": "ScopeSetting.ScopeEnum"
        },
        {
            "name": "doNotDifferentiateProtocols",
            "baseName": "DoNotDifferentiateProtocols",
            "type": "boolean"
        }    ];

    static getAttributeTypeMap() {
        return ScopeSetting.attributeTypeMap;
    }
}

export namespace ScopeSetting {
    export enum DisallowedHttpMethodsEnum {
        Get = <any> 'GET',
        Post = <any> 'POST',
        Connect = <any> 'CONNECT',
        Head = <any> 'HEAD',
        Trace = <any> 'TRACE',
        Debug = <any> 'DEBUG',
        Track = <any> 'TRACK',
        Put = <any> 'PUT',
        Options = <any> 'OPTIONS',
        Delete = <any> 'DELETE',
        Link = <any> 'LINK',
        Unlink = <any> 'UNLINK',
        Patch = <any> 'PATCH'
    }
    export enum ScopeEnum {
        EnteredPathAndBelow = <any> 'EnteredPathAndBelow',
        OnlyEnteredUrl = <any> 'OnlyEnteredUrl',
        WholeDomain = <any> 'WholeDomain'
    }
}
