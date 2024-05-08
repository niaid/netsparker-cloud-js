/* tslint:disable */
/* eslint-disable */
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

import { mapValues } from '../runtime';
import type { SequenceViewModel } from './SequenceViewModel';
import {
    SequenceViewModelFromJSON,
    SequenceViewModelFromJSONTyped,
    SequenceViewModelToJSON,
} from './SequenceViewModel';

/**
 * Business Logic Recorder Setting Model
 * @export
 * @interface BusinessLogicRecorderSettingModel
 */
export interface BusinessLogicRecorderSettingModel {
    /**
     * Gets or sets the sequence model list.
     * @type {Array<SequenceViewModel>}
     * @memberof BusinessLogicRecorderSettingModel
     */
    sequenceModelList?: Array<SequenceViewModel>;
}

/**
 * Check if a given object implements the BusinessLogicRecorderSettingModel interface.
 */
export function instanceOfBusinessLogicRecorderSettingModel(value: object): boolean {
    return true;
}

export function BusinessLogicRecorderSettingModelFromJSON(json: any): BusinessLogicRecorderSettingModel {
    return BusinessLogicRecorderSettingModelFromJSONTyped(json, false);
}

export function BusinessLogicRecorderSettingModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): BusinessLogicRecorderSettingModel {
    if (json == null) {
        return json;
    }
    return {
        
        'sequenceModelList': json['SequenceModelList'] == null ? undefined : ((json['SequenceModelList'] as Array<any>).map(SequenceViewModelFromJSON)),
    };
}

export function BusinessLogicRecorderSettingModelToJSON(value?: BusinessLogicRecorderSettingModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'SequenceModelList': value['sequenceModelList'] == null ? undefined : ((value['sequenceModelList'] as Array<any>).map(SequenceViewModelToJSON)),
    };
}

