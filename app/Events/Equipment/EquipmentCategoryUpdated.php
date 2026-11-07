<?php

namespace App\Events\Equipment;

use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Models\EquipmentCategory;
use App\Models\User;

/**
 * An equipment category was renamed.
 */
class EquipmentCategoryUpdated extends AbstractDomainEvent
{
    public function __construct(public EquipmentCategory $category, public ChangeSet $changes, ?User $actor)
    {
        parent::__construct($actor);
    }

    /**
     * Announce what the last save of the category changed. A save that changed nothing is not announced.
     */
    public static function dispatchChanges(EquipmentCategory $category, ?User $actor): void
    {
        $changes = ChangeSet::fromModel($category);

        if ($changes->isNotEmpty()) {
            static::dispatch($category, $changes, $actor);
        }
    }
}
