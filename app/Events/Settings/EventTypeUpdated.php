<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Events\EventDescription;
use App\Models\EventType;
use App\Models\User;

/**
 * An event type was renamed, moved under another parent, hidden or shown again.
 */
class EventTypeUpdated extends AbstractDomainEvent
{
    /**
     * The event type's attributes as they are named in a notice. Attributes without a label
     * (or announced by an event of their own) are not mentioned.
     *
     * @var array<string, string>
     */
    private const LABELS = [
        'name' => 'название',
        'parent_id' => 'родительский тип',
        'is_active' => 'доступность',
    ];

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

    public function describe(): ?EventDescription
    {
        $changed = self::changedLabels($this->changes, self::LABELS);

        if ($changed === null) {
            return null;
        }

        return new EventDescription("Изменён тип занятий «{$this->eventType->full_name}»: {$changed}", route('settings.event-types.index'), []);
    }
}
