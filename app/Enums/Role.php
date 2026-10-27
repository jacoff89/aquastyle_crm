<?php

namespace App\Enums;

enum Role: string
{
    case Admin = 'admin';
    case Instructor = 'instructor';

    /**
     * Human-readable role name shown in the interface.
     */
    public function label(): string
    {
        return match ($this) {
            self::Admin => 'Администратор',
            self::Instructor => 'Инструктор',
        };
    }
}
