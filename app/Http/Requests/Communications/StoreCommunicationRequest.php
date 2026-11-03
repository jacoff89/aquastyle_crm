<?php

namespace App\Http\Requests\Communications;

use App\Models\Communication;

class StoreCommunicationRequest extends CommunicationRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('create', [Communication::class, $this->route('client')]);
    }
}
