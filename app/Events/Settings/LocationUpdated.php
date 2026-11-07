<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Events\EventDescription;
use App\Models\Location;
use App\Models\User;

/**
 * A location was renamed, given another address, hidden or shown again.
 */
class LocationUpdated extends AbstractDomainEvent
{
    /**
     * The location's attributes as they are named in a notice. Attributes without a label
     * (or announced by an event of their own) are not mentioned.
     *
     * @var array<string, string>
     */
    private const LABELS = [
        'name' => 'название',
        'address' => 'адрес',
        'is_active' => 'доступность',
    ];

    public function __construct(public Location $location, public ChangeSet $changes, ?User $actor)
    {
        parent::__construct($actor);
    }

    /**
     * Announce what the last save of the location changed. A save that changed nothing is not announced.
     */
    public static function dispatchChanges(Location $location, ?User $actor): void
    {
        $changes = ChangeSet::fromModel($location);

        if ($changes->isNotEmpty()) {
            static::dispatch($location, $changes, $actor);
        }
    }

    public function describe(): ?EventDescription
    {
        $changed = self::changedLabels($this->changes, self::LABELS);

        if ($changed === null) {
            return null;
        }

        return new EventDescription("Изменена локация «{$this->location->name}»: {$changed}", route('locations.index'), []);
    }
}
