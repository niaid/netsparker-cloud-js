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
import { IdNamePair } from './idNamePair';
/**
* Represents a model for carrying out website data.
*/
export declare class WebsiteApiModel {
    /**
    * Gets or sets the website identifier.
    */
    'id'?: string;
    /**
    * Gets or sets the date which this website was created at.
    */
    'createdAt'?: Date;
    /**
    * Gets or sets the date which this website was updated at.
    */
    'updatedAt'?: Date;
    /**
    * Gets or sets the root domain URL.
    */
    'rootUrl'?: string;
    /**
    * Gets or sets a name for this website.
    */
    'name'?: string;
    /**
    * Gets or sets a name for this description.
    */
    'description'?: string;
    /**
    * Gets or sets the technical contact email.
    */
    'technicalContactEmail'?: string;
    /**
    * Gets or sets the name of groups this website will belong to.
    */
    'groups'?: Array<IdNamePair>;
    /**
    * Gets or sets a value indicating whether this website is verified.
    */
    'isVerified'?: boolean;
    /**
    * Gets or sets the type of the subscription.
    */
    'licenseType'?: WebsiteApiModel.LicenseTypeEnum;
    /**
    * Gets or sets the agent mode.
    */
    'agentMode'?: WebsiteApiModel.AgentModeEnum;
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
export declare namespace WebsiteApiModel {
    enum LicenseTypeEnum {
        Subscription,
        Credit
    }
    enum AgentModeEnum {
        Cloud,
        Internal
    }
}