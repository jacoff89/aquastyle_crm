<?php

namespace App\Events\Equipment;

use App\Events\AbstractDomainEvent;
use App\Models\EquipmentCategory;
use App\Models\User;

/**
 * An equipment category was added.
 */
class EquipmentCategoryCreated extends AbstractDomainEvent
{
    public function __construct(public EquipmentCategory $category, ?User $actor)
    {
        parent::__construct($actor);
    }
}
