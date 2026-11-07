<?php

namespace App\Events\Equipment;

use App\Events\AbstractDomainEvent;
use App\Models\Equipment;
use App\Models\User;

/**
 * An item was assigned to another instructor, assigned for the first time, or taken back
 * from an instructor. The new instructor is on the item (none when it was taken back);
 * the previous one is carried here.
 */
class EquipmentAssigned extends AbstractDomainEvent
{
    public function __construct(public Equipment $equipment, public ?int $previousInstructorId, ?User $actor)
    {
        parent::__construct($actor);
    }
}
