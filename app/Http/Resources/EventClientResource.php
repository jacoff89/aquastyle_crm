<?php

namespace App\Http\Resources;

use App\Models\EventClient;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * A client in the list of an event's window. Expects `client` to be loaded.
 *
 * @mixin EventClient
 */
class EventClientResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'clientId' => $this->client_id,
            'name' => $this->client->fullName(),
            'phone' => $this->client->phone,
            'isDeleted' => $this->client->trashed(),
            'status' => $this->status->value,
            'statusLabel' => $this->status->label(),
            'isAttendanceMark' => $this->status->isAttendanceMark(),
            'notes' => $this->notes,
        ];
    }
}
