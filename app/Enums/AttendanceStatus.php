<?php

namespace App\Enums;

/**
 * Where a client stands on an event: booked, then attended or not,
 * or cancelled by the client.
 */
enum AttendanceStatus: string
{
    case Booked = 'booked';
    case Attended = 'attended';
    case NoShow = 'no_show';
    case Cancelled = 'cancelled';

    /**
     * Human-readable status shown in the interface.
     */
    public function label(): string
    {
        return match ($this) {
            self::Booked => 'Записан',
            self::Attended => 'Пришёл',
            self::NoShow => 'Не пришёл',
            self::Cancelled => 'Отменил',
        };
    }

    /**
     * Whether the client takes one of the event's places. A client who cancelled
     * or did not come frees the place.
     */
    public function occupiesPlace(): bool
    {
        return match ($this) {
            self::Booked, self::Attended => true,
            self::NoShow, self::Cancelled => false,
        };
    }

    /**
     * Whether the status records what happened at the event. Only these are
     * limited to administrators and the event's own instructors.
     */
    public function isAttendanceMark(): bool
    {
        return $this === self::Attended || $this === self::NoShow;
    }

    /**
     * Values of the statuses that take a place, for queries.
     *
     * @return list<string>
     */
    public static function occupyingValues(): array
    {
        return array_map(
            fn (self $status): string => $status->value,
            array_filter(self::cases(), fn (self $status): bool => $status->occupiesPlace()),
        );
    }
}
