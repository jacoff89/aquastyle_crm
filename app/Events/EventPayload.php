<?php

namespace App\Events;

use BackedEnum;
use DateTimeInterface;
use Illuminate\Database\Eloquent\Model;

/**
 * A domain event's data in a plain form that can be logged or stored as JSON:
 * models as "Client#12", change sets as arrays, enums as their values.
 * Who made the change and when are left out: they are stored on their own.
 */
final class EventPayload
{
    /**
     * @return array<string, mixed>
     */
    public static function of(DomainEvent $event): array
    {
        $payload = [];

        foreach (get_object_vars($event) as $name => $value) {
            if (! in_array($name, ['actor', 'occurredAt'], true)) {
                $payload[$name] = self::plain($value);
            }
        }

        return $payload;
    }

    private static function plain(mixed $value): mixed
    {
        return match (true) {
            $value instanceof Model => class_basename($value).'#'.$value->getKey(),
            $value instanceof ChangeSet => $value->toArray(),
            $value instanceof BackedEnum => $value->value,
            $value instanceof DateTimeInterface => $value->format('Y-m-d H:i:s'),
            is_array($value) => array_map(self::plain(...), $value),
            default => $value,
        };
    }
}
