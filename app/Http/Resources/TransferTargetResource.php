<?php

namespace App\Http\Resources;

use App\Actions\FindInstructorConflicts;
use App\Models\Event;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * An event a client can be moved to, as the move picker lists it. Expects `type` and `instructors`
 * to be loaded, the `occupied_places` count (see Event::withOccupiedPlacesCount()) and the
 * `has_client` flag: whether the client being moved is already on the event.
 *
 * @mixin Event
 */
class TransferTargetResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $lead = $this->leadInstructor();
        $occupied = (int) $this->occupied_places;

        return [
            'id' => $this->id,
            'title' => $this->displayTitle(),
            'period' => FindInstructorConflicts::period($this->starts_at, $this->ends_at),
            'location' => $this->location,
            'leadName' => $lead?->fullName(),
            'color' => $lead?->color,
            'capacity' => $this->capacity,
            'occupiedPlaces' => $occupied,
            'isFull' => $this->capacity !== null && $occupied >= $this->capacity,
            'hasClient' => (bool) $this->has_client,
        ];
    }
}
