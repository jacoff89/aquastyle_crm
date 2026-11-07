<?php

namespace App\Listeners;

use App\Events\DomainEvent;
use App\Events\EventPayload;
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
        Log::channel('events')->info(class_basename($event), [
            'actor' => $event->actor()?->getKey(),
            'occurred_at' => $event->occurredAt()->format('Y-m-d H:i:s'),
            ...EventPayload::of($event),
        ]);
    }
}
