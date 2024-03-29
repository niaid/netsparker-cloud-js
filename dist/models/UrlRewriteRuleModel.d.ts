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
/**
 * Represents an URL Rewrite rule.
 * @export
 * @interface UrlRewriteRuleModel
 */
export interface UrlRewriteRuleModel {
    /**
     * Gets or sets the path placeholders.
     * @type {string}
     * @memberof UrlRewriteRuleModel
     */
    placeholderPattern?: string;
    /**
     * Gets or sets the pattern.
     * @type {string}
     * @memberof UrlRewriteRuleModel
     */
    regexPattern?: string;
}
/**
 * Check if a given object implements the UrlRewriteRuleModel interface.
 */
export declare function instanceOfUrlRewriteRuleModel(value: object): boolean;
export declare function UrlRewriteRuleModelFromJSON(json: any): UrlRewriteRuleModel;
export declare function UrlRewriteRuleModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): UrlRewriteRuleModel;
export declare function UrlRewriteRuleModelToJSON(value?: UrlRewriteRuleModel | null): any;
