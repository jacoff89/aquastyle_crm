<?php

namespace App\Events\Equipment;

use App\Enums\EquipmentStatus;
use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Models\Equipment;
use App\Models\User;

/**
 * An item in the equipment registry was edited. The changes that matter on their own are
 * announced by their own events as well: EquipmentAssigned and EquipmentStatusChanged.
 */
class EquipmentUpdated extends AbstractDomainEvent
{
    public function __construct(public Equipment $equipment, public ChangeSet $changes, ?User $actor)
    {
        parent::__construct($actor);
    }

    /**
     * Announce what the last save of the item changed, followed by the events for a new
     * instructor and a new status. A save that changed nothing is not announced.
     */
    public static function dispatchChanges(Equipment $equipment, ?User $actor): void
    {
        $changes = ChangeSet::fromModel($equipment);

        if ($changes->isEmpty()) {
            return;
        }

        static::dispatch($equipment, $changes, $actor);

        if ($changes->has('instructor_id')) {
            $previousInstructorId = $changes->old('instructor_id');

            EquipmentAssigned::dispatch($equipment, $previousInstructorId === null ? null : (int) $previousInstructorId, $actor);
        }

        if ($changes->has('status')) {
            EquipmentStatusChanged::dispatch($equipment, EquipmentStatus::from($changes->old('status')), $actor);
        }
    }
}
