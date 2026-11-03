<?php

namespace App\Http\Requests\Communications;

class UpdateCommunicationRequest extends CommunicationRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('update', $this->route('communication'));
    }
}
