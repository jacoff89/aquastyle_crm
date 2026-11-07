<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Models\EventType;
use App\Models\User;

/**
 * An event type was renamed, moved under another parent, hidden or shown again.
 */
class EventTypeUpdated extends AbstractDomainEvent
{
    public function __construct(public EventType $eventType, public ChangeSet $changes, ?User $actor)
    {
        parent::__construct($actor);
    }

    /**
     * Announce what the last save of the event type changed. A save that changed nothing is not announced.
     */
    public static function dispatchChanges(EventType $eventType, ?User $actor): void
    {
        $changes = ChangeSet::fromModel($eventType);

        if ($changes->isNotEmpty()) {
            static::dispatch($eventType, $changes, $actor);
        }
    }
}
