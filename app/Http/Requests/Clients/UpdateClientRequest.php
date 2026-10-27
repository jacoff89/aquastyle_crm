<?php

namespace App\Http\Requests\Clients;

use App\Models\Client;

class UpdateClientRequest extends ClientRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('update', $this->client());
    }

    protected function ignoredClient(): ?Client
    {
        return $this->client();
    }

    private function client(): Client
    {
        return $this->route('client');
    }
}
