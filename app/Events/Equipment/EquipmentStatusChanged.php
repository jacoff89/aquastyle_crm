<?php

namespace App\Events\Equipment;

use App\Enums\EquipmentStatus;
use App\Events\AbstractDomainEvent;
use App\Models\Equipment;
use App\Models\User;

/**
 * An item got another status: sent for repair, written off or put back in use.
 * The new status is on the item; the previous one is carried here.
 */
class EquipmentStatusChanged extends AbstractDomainEvent
{
    public function __construct(public Equipment $equipment, public EquipmentStatus $previousStatus, ?User $actor)
    {
        parent::__construct($actor);
    }
}
