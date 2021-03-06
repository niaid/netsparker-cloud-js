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

/**
* Represents a model for carrying out HTTP request settings.
*/
export class HttpRequestSettingModel {
    /**
    * Gets or sets the accept.
    */
    'accept'?: string;
    /**
    * Gets or sets the accept charset.
    */
    'acceptCharset'?: string;
    /**
    * Gets or sets the accept language.
    */
    'acceptLanguage'?: string;
    /**
    * Gets or sets a value indicating whether cookies are disabled.
    */
    'enableCookies'?: boolean;
    /**
    * Gets or sets a value indicating whether gzip and deflate is enabled.
    */
    'enableGzipAndDeflate'?: boolean;
    /**
    * Gets or sets a value indicating whether HTTP keep alive is enabled.
    */
    'httpKeepAlive'?: boolean;
    /**
    * Gets or sets a value indicating whether cookies are disabled.
    */
    'logHttpRequests'?: boolean;
    /**
    * Gets or sets the request count per unit time.
    */
    'requestsPerSecond'?: number;
    /**
    * Gets or sets the concurrent connection count.
    */
    'concurrentConnectionCount'?: number;
    /**
    * Gets or sets the request timeout in seconds.
    */
    'requestTimeout'?: number;
    /**
    * Gets or sets the connection timeout in seconds.
    */
    'connectionTimeout'?: number;
    /**
    * Gets or sets the user agent.
    */
    'userAgent'?: string;
    /**
    * Gets or sets the user agents.
    */
    'userAgents'?: { [key: string]: string; };
    /**
    * Gets or sets a value indicating whether user agent forced.
    */
    'forceUserAgent'?: boolean;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "accept",
            "baseName": "Accept",
            "type": "string"
        },
        {
            "name": "acceptCharset",
            "baseName": "AcceptCharset",
            "type": "string"
        },
        {
            "name": "acceptLanguage",
            "baseName": "AcceptLanguage",
            "type": "string"
        },
        {
            "name": "enableCookies",
            "baseName": "EnableCookies",
            "type": "boolean"
        },
        {
            "name": "enableGzipAndDeflate",
            "baseName": "EnableGzipAndDeflate",
            "type": "boolean"
        },
        {
            "name": "httpKeepAlive",
            "baseName": "HttpKeepAlive",
            "type": "boolean"
        },
        {
            "name": "logHttpRequests",
            "baseName": "LogHttpRequests",
            "type": "boolean"
        },
        {
            "name": "requestsPerSecond",
            "baseName": "RequestsPerSecond",
            "type": "number"
        },
        {
            "name": "concurrentConnectionCount",
            "baseName": "ConcurrentConnectionCount",
            "type": "number"
        },
        {
            "name": "requestTimeout",
            "baseName": "RequestTimeout",
            "type": "number"
        },
        {
            "name": "connectionTimeout",
            "baseName": "ConnectionTimeout",
            "type": "number"
        },
        {
            "name": "userAgent",
            "baseName": "UserAgent",
            "type": "string"
        },
        {
            "name": "userAgents",
            "baseName": "UserAgents",
            "type": "{ [key: string]: string; }"
        },
        {
            "name": "forceUserAgent",
            "baseName": "ForceUserAgent",
            "type": "boolean"
        }    ];

    static getAttributeTypeMap() {
        return HttpRequestSettingModel.attributeTypeMap;
    }
}

