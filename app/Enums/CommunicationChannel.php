<?php

namespace App\Enums;

/**
 * How the dive center got in touch with a client, or the client with it.
 */
enum CommunicationChannel: string
{
    case Phone = 'phone';
    case Messenger = 'messenger';
    case InPerson = 'in_person';
    case Other = 'other';

    /**
     * Human-readable channel shown in the interface.
     */
    public function label(): string
    {
        return match ($this) {
            self::Phone => 'Звонок',
            self::Messenger => 'Мессенджер',
            self::InPerson => 'Личная встреча',
            self::Other => 'Другое',
        };
    }

    /**
     * Value and label of every channel, for the select in the interface.
     *
     * @return list<array{value: string, label: string}>
     */
    public static function options(): array
    {
        return array_map(
            fn (self $channel): array => ['value' => $channel->value, 'label' => $channel->label()],
            self::cases(),
        );
    }
}
