<?php

namespace App\Http\Requests\Equipment;

use App\Models\Equipment;

class StoreEquipmentRequest extends EquipmentRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('create', Equipment::class);
    }
}
