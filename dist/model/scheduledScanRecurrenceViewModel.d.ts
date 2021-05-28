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
* Scheduled scan recurrence view model.
*/
export declare class ScheduledScanRecurrenceViewModel {
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
export declare namespace ScheduledScanRecurrenceViewModel {
    enum RepeatTypeEnum {
        Days,
        Weeks,
        Months,
        Years
    }
    enum EndingTypeEnum {
        Never,
        Date,
        Occurences
    }
    enum DaysOfWeekEnum {
        Sunday,
        Monday,
        Tuesday,
        Wednesday,
        Thursday,
        Friday,
        Saturday
    }
    enum MonthsOfYearEnum {
        January,
        February,
        March,
        April,
        May,
        June,
        July,
        August,
        September,
        October,
        November,
        December
    }
    enum OrdinalEnum {
        First,
        Second,
        Third,
        Fourth,
        Last
    }
    enum DayOfWeekEnum {
        Sunday,
        Monday,
        Tuesday,
        Wednesday,
        Thursday,
        Friday,
        Saturday
    }
}