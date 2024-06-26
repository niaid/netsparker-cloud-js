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
 * Represents a model for carrying out crawling settings.
 * @export
 * @interface CrawlingSettingModel
 */
export interface CrawlingSettingModel {
    /**
     * Gets or sets a value indicating whether parameter based navigation is enabled.
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    enableParameterBasedNavigation?: boolean;
    /**
     * Gets or sets whether REST Web Service parser is enabled.
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    enableRestWebServiceParser?: boolean;
    /**
     * Gets or sets whether SOAP Web Service parser is enabled.
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    enableSoapWebServiceParser?: boolean;
    /**
     * Gets or sets a value indicating whether text parser is enabled.
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    enableTextParser?: boolean;
    /**
     * Gets or sets a value indicating whether "fallback to get" is enabled
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    fallbackToGet?: boolean;
    /**
     * Gets or sets a value indicating whether "fallback to get" is enabled
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    enableFragmentParsing?: boolean;
    /**
     * Gets or sets a value indicating whether "parse javascript" is enabled
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    enableJavascriptParsing?: boolean;
    /**
     * Gets or sets the file extensions that will be used in File Extensions RegEx.
     * @type {string}
     * @memberof CrawlingSettingModel
     */
    fileExtensions?: string;
    /**
     * Gets or sets the maximum crawler URL count.
     * @type {number}
     * @memberof CrawlingSettingModel
     */
    maximumCrawlerUrlCount?: number;
    /**
     * Gets or sets the maximum signature.
     * @type {number}
     * @memberof CrawlingSettingModel
     */
    maximumSignature?: number;
    /**
     * Gets or sets the page visit limit for links containing navigation parameter.
     * @type {number}
     * @memberof CrawlingSettingModel
     */
    navigationParameterPageVisitLimit?: number;
    /**
     * Gets or sets the regular expression pattern for navigation parameter.
     * @type {string}
     * @memberof CrawlingSettingModel
     */
    navigationParameterRegexPattern?: string;
    /**
     * Gets or sets the page visit limit.
     * @type {number}
     * @memberof CrawlingSettingModel
     */
    pageVisitLimit?: number;
    /**
     * Gets or sets the page visit limit.
     * @type {number}
     * @memberof CrawlingSettingModel
     */
    maximumUrlRewriteSignature?: number;
    /**
     * Gets or sets a value indicating whether the crawler should wait resource finder.
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    waitResourceFinder?: boolean;
    /**
     * Specifies whether all related links should be crawled when a new link is found.
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    addRelatedLinks?: boolean;
    /**
     * If enabled, only query string parameters will be recognized as navigation parameters.
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    enableQueryBasedParameterBasedNavigation?: boolean;
}
/**
 * Check if a given object implements the CrawlingSettingModel interface.
 */
export declare function instanceOfCrawlingSettingModel(value: object): boolean;
export declare function CrawlingSettingModelFromJSON(json: any): CrawlingSettingModel;
export declare function CrawlingSettingModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): CrawlingSettingModel;
export declare function CrawlingSettingModelToJSON(value?: CrawlingSettingModel | null): any;
