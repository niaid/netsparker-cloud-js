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
* Represents a model for carrying out javascript settings.
*/
export declare class JavaScriptSettingsModel {
    /**
    * Gets or sets the bail threshold.
    */
    'bailThreshold'?: number;
    /**
    * Gets or sets the confirm open redirect simulate timeout.
    */
    'confirmOpenRedirectSimulateTimeout'?: number;
    /**
    * Gets or sets the confirm xss simulate timeout.
    */
    'confirmXssSimulateTimeout'?: number;
    /**
    * Gets or sets a value indicating whether to allow out of scope XML HTTP requests in DOM Parser.
    */
    'domParserAllowOutOfScopeXmlHttpRequests'?: boolean;
    /**
    * Gets or sets the DOM parser DFS limit.
    */
    'domParserDfsLimit'?: number;
    /**
    * Gets or sets the DOM parser dotify.
    */
    'domParserDotify'?: boolean;
    /**
    * Gets or sets the DOM parser exclusion CSS selector.
    */
    'domParserExclusionCssSelector'?: string;
    /**
    * Gets or sets a value indicating whether to extract resources using DOM Parser.
    */
    'domParserExtractResources'?: boolean;
    /**
    * Gets or sets a value indicating whether to filter events that contain a colon in their names.
    */
    'domParserFilterColonEvents'?: boolean;
    /**
    * Gets or sets the DOM parser filter document events.
    */
    'domParserFilterDocumentEvents'?: boolean;
    /**
    * Gets or sets a value indicating whether to ignore document events in DOM Parser.
    */
    'domParserIgnoreDocumentEvents'?: boolean;
    /**
    * Gets or sets the DOM parser load URL timeout.
    */
    'domParserLoadUrlTimeout'?: number;
    /**
    * Gets or sets the DOM parser maximum option elements per select.
    */
    'domParserMaxOptionElementsPerSelect'?: number;
    /**
    * Gets or sets the DOM parser persistent javascript cookies.
    */
    'domParserPersistentJavaScriptCookies'?: string;
    /**
    * Gets or sets the DOM Parser LoadUrl timeout.
    */
    'domParserPreSimulateWait'?: number;
    /**
    * Gets or sets the DOM parser simulation timeout.
    */
    'domParserSimulationTimeout'?: number;
    /**
    * Gets or sets a value indicating whether enable DOM parser.
    */
    'enableDomParser'?: boolean;
    /**
    * Gets or sets the interevent timeout.
    */
    'intereventTimeout'?: number;
    /**
    * Gets or sets the skip element count.
    */
    'skipElementCount'?: number;
    /**
    * Gets or sets the skip threshold.
    */
    'skipThreshold'?: number;
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
