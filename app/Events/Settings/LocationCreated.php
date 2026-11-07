<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Models\Location;
use App\Models\User;

/**
 * A location was added.
 */
class LocationCreated extends AbstractDomainEvent
{
    public function __construct(public Location $location, ?User $actor)
    {
        parent::__construct($actor);
    }
}
