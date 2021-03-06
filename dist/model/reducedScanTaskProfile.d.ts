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
* Represents a class that carries out basic scan task profile data.
*/
export declare class ReducedScanTaskProfile {
    /**
    * Gets or sets the identifier.
    */
    'id'?: string;
    /**
    * Gets or sets a value indicating whether this scan profile is user\'s profile.
    */
    'isMine'?: boolean;
    /**
    * Gets or sets a value indicating whether this instance is primary scan profile for a website.
    */
    'isPrimary'?: boolean;
    /**
    * Gets or sets a value indicating whether this scan profile is shared to other team members.
    */
    'isShared'?: boolean;
    /**
    * Gets or sets the name.
    */
    'name'?: string;
    /**
    * Gets or sets the target URL.
    */
    'targetUrl'?: string;
    /**
    * Gets or sets the Scan Policy name.
    */
    'scanPolicyName'?: string;
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
