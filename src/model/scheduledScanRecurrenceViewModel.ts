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

import { RequestFile } from './models';

/**
* Scheduled scan recurrence view model.
*/
export class ScheduledScanRecurrenceViewModel {
    /**
    * The {Invicti.Dates.Recurring.Enums.RepeatTypes}.
    */
    'repeatType'?: ScheduledScanRecurrenceViewModel.RepeatTypeEnum;
    /**
    * The interval.
    */
    'interval'?: number;
    /**
    * The start date.
    */
    'startDate'?: Date;
    /**
    * The ending type.
    */
    'endingType'?: ScheduledScanRecurrenceViewModel.EndingTypeEnum;
    /**
    * The day of weeks.
    */
    'daysOfWeek'?: Array<ScheduledScanRecurrenceViewModel.DaysOfWeekEnum>;
    /**
    * The months of year.
    */
    'monthsOfYear'?: Array<ScheduledScanRecurrenceViewModel.MonthsOfYearEnum>;
    /**
    * The ordinals.
    */
    'ordinal'?: ScheduledScanRecurrenceViewModel.OrdinalEnum;
    /**
    * The ending date.
    */
    'endOn'?: string;
    /**
    * The limit of the scheduled scan executions.
    */
    'endOnOccurences'?: number;
    /**
    * The day of month.
    */
    'dayOfMonth'?: number;
    /**
    * The ending date.
    */
    'endOnDate'?: Date;
    /**
    * The recurrence builder.
    */
    'dayOfWeek'?: ScheduledScanRecurrenceViewModel.DayOfWeekEnum;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "repeatType",
            "baseName": "RepeatType",
            "type": "ScheduledScanRecurrenceViewModel.RepeatTypeEnum"
        },
        {
            "name": "interval",
            "baseName": "Interval",
            "type": "number"
        },
        {
            "name": "startDate",
            "baseName": "StartDate",
            "type": "Date"
        },
        {
            "name": "endingType",
            "baseName": "EndingType",
            "type": "ScheduledScanRecurrenceViewModel.EndingTypeEnum"
        },
        {
            "name": "daysOfWeek",
            "baseName": "DaysOfWeek",
            "type": "Array<ScheduledScanRecurrenceViewModel.DaysOfWeekEnum>"
        },
        {
            "name": "monthsOfYear",
            "baseName": "MonthsOfYear",
            "type": "Array<ScheduledScanRecurrenceViewModel.MonthsOfYearEnum>"
        },
        {
            "name": "ordinal",
            "baseName": "Ordinal",
            "type": "ScheduledScanRecurrenceViewModel.OrdinalEnum"
        },
        {
            "name": "endOn",
            "baseName": "EndOn",
            "type": "string"
        },
        {
            "name": "endOnOccurences",
            "baseName": "EndOnOccurences",
            "type": "number"
        },
        {
            "name": "dayOfMonth",
            "baseName": "DayOfMonth",
            "type": "number"
        },
        {
            "name": "endOnDate",
            "baseName": "EndOnDate",
            "type": "Date"
        },
        {
            "name": "dayOfWeek",
            "baseName": "DayOfWeek",
            "type": "ScheduledScanRecurrenceViewModel.DayOfWeekEnum"
        }    ];

    static getAttributeTypeMap() {
        return ScheduledScanRecurrenceViewModel.attributeTypeMap;
    }
}

export namespace ScheduledScanRecurrenceViewModel {
    export enum RepeatTypeEnum {
        Days = <any> 'Days',
        Weeks = <any> 'Weeks',
        Months = <any> 'Months',
        Years = <any> 'Years'
    }
    export enum EndingTypeEnum {
        Never = <any> 'Never',
        Date = <any> 'Date',
        Occurences = <any> 'Occurences'
    }
    export enum DaysOfWeekEnum {
        Sunday = <any> 'Sunday',
        Monday = <any> 'Monday',
        Tuesday = <any> 'Tuesday',
        Wednesday = <any> 'Wednesday',
        Thursday = <any> 'Thursday',
        Friday = <any> 'Friday',
        Saturday = <any> 'Saturday'
    }
    export enum MonthsOfYearEnum {
        January = <any> 'January',
        February = <any> 'February',
        March = <any> 'March',
        April = <any> 'April',
        May = <any> 'May',
        June = <any> 'June',
        July = <any> 'July',
        August = <any> 'August',
        September = <any> 'September',
        October = <any> 'October',
        November = <any> 'November',
        December = <any> 'December'
    }
    export enum OrdinalEnum {
        First = <any> 'First',
        Second = <any> 'Second',
        Third = <any> 'Third',
        Fourth = <any> 'Fourth',
        Last = <any> 'Last'
    }
    export enum DayOfWeekEnum {
        Sunday = <any> 'Sunday',
        Monday = <any> 'Monday',
        Tuesday = <any> 'Tuesday',
        Wednesday = <any> 'Wednesday',
        Thursday = <any> 'Thursday',
        Friday = <any> 'Friday',
        Saturday = <any> 'Saturday'
    }
}