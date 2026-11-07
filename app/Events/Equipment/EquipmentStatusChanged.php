<?php

namespace App\Events\Equipment;

use App\Enums\EquipmentStatus;
use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
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

    public function describe(): ?EventDescription
    {
        $status = mb_strtolower($this->equipment->status->label());
        $previous = mb_strtolower($this->previousStatus->label());

        return new EventDescription(
            'Снаряжение '.self::equipmentLabel($this->equipment).": {$status} (было: {$previous})",
            route('equipment.index'),
            [$this->equipment->instructor_id],
        );
    }
}
