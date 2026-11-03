<?php

namespace App\Enums;

use Carbon\CarbonInterface;

/**
 * How far ahead the schedule on an instructor's page looks. Each person picks their own.
 */
enum ScheduleRange: string
{
    case ThreeDays = '3d';
    case Week = '1w';
    case TwoWeeks = '2w';
    case Month = '1m';
    case ThreeMonths = '3m';

    /**
     * The range used until the person picks another one.
     */
    public static function default(): self
    {
        return self::TwoWeeks;
    }

    /**
     * Human-readable range shown in the interface.
     */
    public function label(): string
    {
        return match ($this) {
            self::ThreeDays => '3 дня',
            self::Week => 'Неделя',
            self::TwoWeeks => '2 недели',
            self::Month => 'Месяц',
            self::ThreeMonths => '3 месяца',
        };
    }

    /**
     * The end of the range that starts on the given day.
     */
    public function endFrom(CarbonInterface $from): CarbonInterface
    {
        return match ($this) {
            self::ThreeDays => $from->copy()->addDays(3),
            self::Week => $from->copy()->addWeek(),
            self::TwoWeeks => $from->copy()->addWeeks(2),
            self::Month => $from->copy()->addMonthNoOverflow(),
            self::ThreeMonths => $from->copy()->addMonthsNoOverflow(3),
        };
    }

    /**
     * Value and label of every range, for the select in the interface.
     *
     * @return list<array{value: string, label: string}>
     */
    public static function options(): array
    {
        return array_map(
            fn (self $range): array => ['value' => $range->value, 'label' => $range->label()],
            self::cases(),
        );
    }
}
