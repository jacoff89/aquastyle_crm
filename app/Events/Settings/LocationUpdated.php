<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Models\Location;
use App\Models\User;

/**
 * A location was renamed, given another address, hidden or shown again.
 */
class LocationUpdated extends AbstractDomainEvent
{
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
}
