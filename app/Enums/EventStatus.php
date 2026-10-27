<?php

namespace App\Enums;

enum EventStatus: string
{
    case Planned = 'planned';
    case Done = 'done';
    case Cancelled = 'cancelled';

    /**
     * Human-readable status shown in the interface.
     */
    public function label(): string
    {
        return match ($this) {
            self::Planned => 'Запланировано',
            self::Done => 'Проведено',
            self::Cancelled => 'Отменено',
        };
    }
}
