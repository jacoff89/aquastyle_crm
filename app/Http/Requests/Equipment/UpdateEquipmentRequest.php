<?php

namespace App\Http\Requests\Equipment;

use App\Models\Equipment;

class UpdateEquipmentRequest extends EquipmentRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('update', $this->editedEquipment());
    }

    protected function editedEquipment(): Equipment
    {
        return $this->route('equipment');
    }
}
