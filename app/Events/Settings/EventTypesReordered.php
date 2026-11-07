<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\EventType;
use App\Models\User;

/**
 * An event type was moved one place up or down the list. The list is renumbered with a bulk
 * update, which Eloquent's model events do not see, so this event is the only trace of it.
 */
class EventTypesReordered extends AbstractDomainEvent
{
    /**
     * @param  'up'|'down'  $direction
     */
    public function __construct(public EventType $eventType, public string $direction, ?User $actor)
    {
        parent::__construct($actor);
    }

    public function describe(): ?EventDescription
    {
        $where = $this->direction === 'up' ? 'выше' : 'ниже';

        return new EventDescription("Тип занятий «{$this->eventType->full_name}» перемещён {$where} в списке", route('settings.event-types.index'));
    }
}
