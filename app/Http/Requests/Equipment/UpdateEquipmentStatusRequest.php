<?php

namespace App\Http\Requests\Equipment;

use App\Enums\EquipmentStatus;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

/**
 * Changing only the status of an item: sent for repair, written off or put back in use.
 */
class UpdateEquipmentStatusRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('updateStatus', $this->route('equipment'));
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            'status' => ['required', Rule::enum(EquipmentStatus::class)],
        ];
    }
}
