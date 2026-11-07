<?php

namespace App\Listeners;

use App\Events\ChangeSet;
use App\Events\DomainEvent;
use BackedEnum;
use DateTimeInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Log;

/**
 * Writes every domain event to the "events" log (storage/logs/events-*.log): which event,
 * who made the change, when, and the event's data with models shown as "Client#12".
 * It shows that the events fire and what they carry until the activity log stores them in the database.
 */
class LogDomainEvent
{
    public function handle(DomainEvent $event): void
    {
        $context = [
            'actor' => $event->actor()?->getKey(),
            'occurred_at' => $event->occurredAt()->format('Y-m-d H:i:s'),
        ];

        foreach (get_object_vars($event) as $name => $value) {
            if (! in_array($name, ['actor', 'occurredAt'], true)) {
                $context[$name] = $this->describe($value);
            }
        }

        Log::channel('events')->info(class_basename($event), $context);
    }

    /**
     * A plain form of an event's property for the log.
     */
    private function describe(mixed $value): mixed
    {
        return match (true) {
            $value instanceof Model => class_basename($value).'#'.$value->getKey(),
            $value instanceof ChangeSet => $value->toArray(),
            $value instanceof BackedEnum => $value->value,
            $value instanceof DateTimeInterface => $value->format('Y-m-d H:i:s'),
            is_array($value) => array_map($this->describe(...), $value),
            default => $value,
        };
    }
}
