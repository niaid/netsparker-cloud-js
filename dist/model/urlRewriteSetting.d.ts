/**
 * Netsparker Enterprise API
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: v1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
import { UrlRewriteExcludedPathModel } from './urlRewriteExcludedPathModel';
import { UrlRewriteRuleModel } from './urlRewriteRuleModel';
/**
* Represents a class that carries out url rewrite settings.
*/
export declare class UrlRewriteSetting {
    /**
    * Gets or sets a value indicating whether Heuristic URL Rewrite support is enabled together with custom URL Rewrite  support.
    */
    'enableHeuristicChecksInCustomUrlRewrite'?: boolean;
    /**
    * Gets or sets the root path maximum dynamic signatures for heuristic URL Rewrite detection.
    */
    'maxDynamicSignatures': number;
    /**
    * Gets or sets the sub path maximum dynamic signatures for heuristic URL Rewrite detection.
    */
    'subPathMaxDynamicSignatures': number;
    /**
    * Gets or sets the extensions that will be analyzed for heuristic URL Rewrite detection.
    */
    'urlRewriteAnalyzableExtensions'?: string;
    /**
    * Gets or sets the block separators for heuristic URL Rewrite detection.
    */
    'urlRewriteBlockSeparators': string;
    /**
    * Gets or sets the URL Rewrite mode.
    */
    'urlRewriteMode'?: UrlRewriteSetting.UrlRewriteModeEnum;
    /**
    * Gets or sets the URL Rewrite rules.
    */
    'urlRewriteRules'?: Array<UrlRewriteRuleModel>;
    /**
    * Gets or sets the URL rewrite excluded rules.
    */
    'urlRewriteExcludedLinks'?: Array<UrlRewriteExcludedPathModel>;
    static discriminator: string | undefined;
    static attributeTypeMap: Array<{
        name: string;
        baseName: string;
        type: string;
    }>;
    static getAttributeTypeMap(): {
        name: string;
        baseName: string;
        type: string;
    }[];
}
export declare namespace UrlRewriteSetting {
    enum UrlRewriteModeEnum {
        None,
        Heuristic,
        Custom
    }
}
