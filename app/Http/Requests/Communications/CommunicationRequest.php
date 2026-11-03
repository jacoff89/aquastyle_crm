<?php

namespace App\Http\Requests\Communications;

use App\Enums\CommunicationChannel;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

abstract class CommunicationRequest extends FormRequest
{
    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            'channel' => ['required', Rule::enum(CommunicationChannel::class)],
            'occurred_at' => ['required', 'date_format:Y-m-d\TH:i'],
            'notes' => ['required', 'string', 'max:5000'],
        ];
    }

    /**
     * @return array<string, string>
     */
    public function attributes(): array
    {
        return [
            'channel' => 'Способ связи',
            'occurred_at' => 'Дата и время',
            'notes' => 'Содержание',
        ];
    }

    protected function prepareForValidation(): void
    {
        $this->merge(['notes' => trim((string) $this->input('notes'))]);
    }
}
