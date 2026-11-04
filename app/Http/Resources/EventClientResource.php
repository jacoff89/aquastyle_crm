<?php

namespace App\Http\Resources;

use App\Models\EventClient;
use App\Models\Exercise;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * A client in the list of an event's window. Expects `client` and `exercises` to be loaded
 * and `exerciseIdsDoneElsewhere` to be filled by EventClient::loadExercisesDoneElsewhere().
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
            'exercises' => $this->exercises->map(fn (Exercise $exercise): array => ['id' => $exercise->id, 'name' => $exercise->name])->all(),
            'exerciseIdsDoneElsewhere' => $this->resource->exerciseIdsDoneElsewhere,
        ];
    }
}
