<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
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

    public function describe(): ?EventDescription
    {
        return new EventDescription("Новая локация «{$this->location->name}»", route('locations.index'));
    }
}
