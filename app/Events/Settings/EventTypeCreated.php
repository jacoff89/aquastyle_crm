<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\EventType;
use App\Models\User;

/**
 * An event type was added in the settings.
 */
class EventTypeCreated extends AbstractDomainEvent
{
    public function __construct(public EventType $eventType, ?User $actor)
    {
        parent::__construct($actor);
    }

    public function describe(): ?EventDescription
    {
        return new EventDescription("Новый тип занятий «{$this->eventType->full_name}»", route('settings.event-types.index'));
    }
}
