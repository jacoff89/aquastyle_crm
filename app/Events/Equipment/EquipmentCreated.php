<?php

namespace App\Events\Equipment;

use App\Events\AbstractDomainEvent;
use App\Models\Equipment;
use App\Models\User;

/**
 * An item was added to the equipment registry. When it is assigned to an instructor right away,
 * EquipmentAssigned is dispatched as well.
 */
class EquipmentCreated extends AbstractDomainEvent
{
    public function __construct(public Equipment $equipment, ?User $actor)
    {
        parent::__construct($actor);
    }
}
