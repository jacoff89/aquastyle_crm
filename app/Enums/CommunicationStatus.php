<?php

namespace App\Enums;

/**
 * Whether a contact with a client is still ahead or has already taken place.
 */
enum CommunicationStatus: string
{
    case Planned = 'planned';
    case Completed = 'completed';

    /**
     * Human-readable status shown in the interface.
     */
    public function label(): string
    {
        return match ($this) {
            self::Planned => 'Планируется',
            self::Completed => 'Выполнена',
        };
    }

    /**
     * Value and label of every status, for the select in the interface.
     *
     * @return list<array{value: string, label: string}>
     */
    public static function options(): array
    {
        return array_map(
            fn (self $status): array => ['value' => $status->value, 'label' => $status->label()],
            self::cases(),
        );
    }
}
