<?php

namespace App\Events\Equipment;

use App\Enums\EquipmentStatus;
use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Events\EventDescription;
use App\Models\Equipment;
use App\Models\User;

/**
 * An item in the equipment registry was edited. The changes that matter on their own are
 * announced by their own events as well: EquipmentAssigned and EquipmentStatusChanged.
 */
class EquipmentUpdated extends AbstractDomainEvent
{
    /**
     * The item's attributes as they are named in a notice. Attributes without a label
     * (or announced by an event of their own) are not mentioned.
     *
     * @var array<string, string>
     */
    private const LABELS = [
        'name' => 'название',
        'category_id' => 'категория',
        'inventory_number' => 'инвентарный номер',
        'size' => 'размер',
        'location_id' => 'место хранения',
        'notes' => 'заметки',
    ];

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

    public function describe(): ?EventDescription
    {
        $changed = self::changedLabels($this->changes, self::LABELS);

        if ($changed === null) {
            return null;
        }

        return new EventDescription('Изменено снаряжение '.self::equipmentLabel($this->equipment).": {$changed}", route('equipment.index'), [$this->equipment->instructor_id]);
    }
}
