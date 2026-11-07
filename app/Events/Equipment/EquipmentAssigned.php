<?php

namespace App\Events\Equipment;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\Equipment;
use App\Models\User;

/**
 * An item was assigned to another instructor, assigned for the first time, or taken back
 * from an instructor. The new instructor is on the item (none when it was taken back);
 * the previous one is carried here.
 *
 * An item added with an instructor is announced with `forNewItem` set; it gives no description then,
 * because the description of EquipmentCreated already reaches that instructor.
 */
class EquipmentAssigned extends AbstractDomainEvent
{
    public function __construct(public Equipment $equipment, public ?int $previousInstructorId, ?User $actor, public bool $forNewItem = false)
    {
        parent::__construct($actor);
    }

    public function describe(): ?EventDescription
    {
        if ($this->forNewItem) {
            return null;
        }

        $item = 'Снаряжение '.self::equipmentLabel($this->equipment);
        $instructorId = $this->equipment->instructor_id;

        $text = match (true) {
            $instructorId === null => "{$item} больше не закреплено за ".self::userNames([$this->previousInstructorId]),
            $this->previousInstructorId === null => "{$item} закреплено за ".self::userNames([$instructorId]),
            default => "{$item} закреплено за ".self::userNames([$instructorId]).' вместо '.self::userNames([$this->previousInstructorId]),
        };

        return new EventDescription($text, route('equipment.index'), [$instructorId, $this->previousInstructorId]);
    }
}
