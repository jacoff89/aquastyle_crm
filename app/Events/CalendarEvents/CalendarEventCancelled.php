<?php

namespace App\Events\CalendarEvents;

use App\Enums\EventStatus;
use App\Events\AbstractDomainEvent;
use App\Models\Event;
use App\Models\User;

/**
 * An event was cancelled. Its clients stay on it, and their statuses can now only be set to cancelled.
 */
class CalendarEventCancelled extends AbstractDomainEvent
{
    public function __construct(public Event $event, public EventStatus $previousStatus, ?User $actor)
    {
        parent::__construct($actor);
    }
}
