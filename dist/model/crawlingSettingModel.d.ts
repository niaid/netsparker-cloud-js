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
/**
* Represents a model for carrying out crawling settings.
*/
export declare class CrawlingSettingModel {
    /**
    * Gets or sets a value indicating whether parameter based navigation is enabled.
    */
    'enableParameterBasedNavigation'?: boolean;
    /**
    * Gets or sets whether REST Web Service parser is enabled.
    */
    'enableRestWebServiceParser'?: boolean;
    /**
    * Gets or sets whether SOAP Web Service parser is enabled.
    */
    'enableSoapWebServiceParser'?: boolean;
    /**
    * Gets or sets a value indicating whether text parser is enabled.
    */
    'enableTextParser'?: boolean;
    /**
    * Gets or sets a value indicating whether \"fallback to get\" is enabled
    */
    'fallbackToGet'?: boolean;
    /**
    * Gets or sets a value indicating whether \"fallback to get\" is enabled
    */
    'enableFragmentParsing'?: boolean;
    /**
    * Gets or sets the file extensions that will be used in File Extensions RegEx.
    */
    'fileExtensions'?: string;
    /**
    * Gets or sets the maximum crawler URL count.
    */
    'maximumCrawlerUrlCount'?: number;
    /**
    * Gets or sets the maximum signature.
    */
    'maximumSignature'?: number;
    /**
    * Gets or sets the page visit limit for links containing navigation parameter.
    */
    'navigationParameterPageVisitLimit'?: number;
    /**
    * Gets or sets the regular expression pattern for navigation parameter.
    */
    'navigationParameterRegexPattern'?: string;
    /**
    * Gets or sets the page visit limit.
    */
    'pageVisitLimit'?: number;
    /**
    * Gets or sets the page visit limit.
    */
    'maximumUrlRewriteSignature'?: number;
    /**
    * Gets or sets a value indicating whether the crawler should wait resource finder.
    */
    'waitResourceFinder'?: boolean;
    /**
    * Specifies whether all related links should be crawled when a new link is found.
    */
    'addRelatedLinks'?: boolean;
    /**
    * If enabled, only query string parameters will be recognized as navigation parameters.
    */
    'enableQueryBasedParameterBasedNavigation'?: boolean;
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
