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
import { CvssScoreValue } from './cvssScoreValue';

/**
* Represents base model for a CVSS entity.
*/
export class CvssMetricModel {
    'score'?: CvssScoreValue;
    /**
    * Gets or sets the metrics of a cvss
    */
    'metrics'?: { [key: string]: string; };

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "score",
            "baseName": "Score",
            "type": "CvssScoreValue"
        },
        {
            "name": "metrics",
            "baseName": "Metrics",
            "type": "{ [key: string]: string; }"
        }    ];

    static getAttributeTypeMap() {
        return CvssMetricModel.attributeTypeMap;
    }
}

